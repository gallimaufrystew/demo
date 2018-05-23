/*****************************
    SSL_IO_Loop

    read/write to an SSL connection. 
    Should be called in its own thread (SSL_Thread in a derived class)

    A single buffer is used for reading from this socket since it is immediately handled

    For writing, call GetEmptySSLemptyBuff to get id of an empty buffer, 
    set it and then GetReadySSLemptyBuff will feed it to this function for sending
    Those two functions maintain the ordering of packets

    uses StayAlive counters and messages to determine if other end is still there

    ***********************/
void SSL_IO_Loop(TunnelInstance tunnelInstance, HANDLE* quitEvents, int numHandles, const SessionID* const sessID)
{	
    // Setup an exception translator to catch WIN32 exceptions.
    _se_translator_function pTranslator = _set_se_translator(SEHExceptionToCPPException);

    // holds the AUTH channel
	LocalPort* authChannel = 0;
	
	char sslStrBuff[16];
	itoa((int)tunnelInstance.ssl, sslStrBuff,10);

    // flags set by CheckSSL_Port() that poll for SSL I/O status
    bool can_read = 0;
    bool can_write = 0;

    // flags to mark all the combinations of why we're blocking 
    unsigned int read_waiton_write = 0;
    unsigned int read_waiton_read = 0;

    unsigned int write_waiton_write = 0;
    unsigned int write_waiton_read = 0;

    // return value of an SSL I/O operation 
    int code;
	int numCantReadOrWrites = 0;
	
    // make the underlying I/O layer behind each SSL object non-blocking
    SetBlocking(tunnelInstance.ssl, false);
    SSL_set_mode(tunnelInstance.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER); 

    // define timer values for the stay alive mechanism.
    DWORD pingCtr = GetTickCount();
    DWORD notAliveCtr = GetTickCount();

	const int SEND_ALIVE_TRIGGER = KodakSecureTunnel::config.StayAliveInterval(); 
	const int DIE_TRIGGER = KodakSecureTunnel::config.StayLiveTolerance() * SEND_ALIVE_TRIGGER;
	const int SLEEPTIME = KodakSecureTunnel::config.SleepInterval();

    HANDLE hReadCapture = NULL;
    HANDLE hWriteCapture = NULL;
    bool bCaptureData = KodakSecureTunnel::config.CaptureData();

	int sendBuffID = -1;
	int sendMessages = 0;

    SSL_BUFFER sslReadBuffer(0);
    SSL_BUFFER sslWriteBuffer(0);
	try
    {
		while (1)
        {
            // Allow other threads to process data.
            Sleep(0);

#ifndef _DEBUG
    		if ((GetTickCount() > notAliveCtr + DIE_TRIGGER))
            {
                // tracks how long its been since message IN
    			throw("Stay Alive check failed\n");
    		}
#endif
    		// check to see if we should shut down
			//Begin:add by Xiaobing.Yu code for 38851 38594 2008.4.23
    		//if (WAIT_TIMEOUT != WaitForMultipleObjects(numHandles, quitEvents,false,0))
			//	throw("Quit Event in SSL_IO_LOOP\n");
			switch (WaitForMultipleObjects(numHandles, quitEvents, false, 0))
			{
				case WAIT_TIMEOUT:
					break;
				case WAIT_OBJECT_0 + 2:	//inactive timeout
					if (authChannel)
					{
						SendString(SEND_REMOTE_SESS_TIMEOUT, authChannel);
						ResetEvent(quitEvents[2]);
					}
					else
						LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Got a Send Inactivity Timeout trigger without an AUTH channel."));
					break;
				default:
					throw("Quit Event in SSL_IO_LOOP\n");
					break;
			}
			//End:add by Xiaobing.Yu code for 38851 38594 2008.4.23
			
			if (sendMessages)
            {
				sendMessages--;
				if (!sendMessages)
					throw("Authentication error\n");
			}
			/* check I/O availability and set flags */
			CheckSSL_Port(tunnelInstance.ssl, can_read, can_write);
    		if (!can_read && !can_write)
            {
				LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() !can_read && !can_write"));
				numCantReadOrWrites++;
				if (numCantReadOrWrites > 2)
					LLOGDEBUG(_T("The Secure connection cannot send or receive"));
    		}
            else
            {
				// LET'S READ AND WRITE!!

                // READING

    			/* this "if" statement reads data. it will only be entered if
    			 * the following conditions are all true:
    			 *  - we're not in the middle of a write
    			 *  - there's something to read OR we are trying to read and we need to write first and we can
    			 */
				numCantReadOrWrites =0;
    			if (!(write_waiton_read || write_waiton_write) &&
    				(can_read || (can_write && read_waiton_write)))
    			{
					try
                    {
                        //READ block
    				    // clear the flags since we'll set them based on the read call's return
    					read_waiton_read = 0;
    					read_waiton_write = 0;

    					// read into the buffer starting at .appsig, read enough for the appsig, connectionID, and the data
                        sslReadBuffer.Reset();
    					code = SSL_read(tunnelInstance.ssl, sslReadBuffer.appsig, sslReadBuffer.GetTotalSize());
    					switch (SSL_get_error(tunnelInstance.ssl, code))
    					{
    						case SSL_ERROR_NONE:
    						{
    							LocalPort* port = GetPortFromAppSig(sslReadBuffer.appsig, sslReadBuffer.appPortID, sslReadBuffer.connID, tunnelInstance);
								sslReadBuffer.len = code - SOCKET_ID_SZ;
								if (port && (port->Socket() != AUTH_SOCKET))
                                {
									if (sslReadBuffer.Empty())
                                    {
										// all done with forwarding, so tell it we won't send anymore
                                        port->FinishedSending();
									}
                                    else
                                    {
										if (sslReadBuffer.len == (long)strlen(NU_CONN_MSSG))
                                        {
											if (!memcmp(sslReadBuffer.data, NU_CONN_MSSG, strlen(NU_CONN_MSSG)))
                                            {
                                                // ignore this message, it just starts the connection
												break;
											}
										}
                                        if (bCaptureData)
                                        {
										    // Write the data to the capture file
                                            if (!hReadCapture)
                                            {
                                                hReadCapture = CreateFile("c:\\SecureLink Read Capture",
                                                                 GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                                                 FILE_ATTRIBUTE_NORMAL, NULL);
                                            }
                                            else
                                            {
                                                DWORD dwBytesWritten;
                                                WriteFile(hReadCapture, sslReadBuffer.appsig,
                                                    sslReadBuffer.GetTotalSize(), &dwBytesWritten, NULL);
                                            }
                                        }
										// Write the data to localhost port
										DWORD dwBytesSent = 0L;
										while (!sslReadBuffer.Empty())
                                        {
                                            // TCP
                                            HANDLE hSendCompleted = ::CreateEvent(NULL, true, false, NULL);
                                            WSABUF wsaBuffer;
                                            wsaBuffer.len = sslReadBuffer.len;
                                            wsaBuffer.buf = (char *) &sslReadBuffer.data[dwBytesSent];
                                            WSAOVERLAPPED wsaOverlap;
											DWORD dwIterBytesSent = 0;
                                            wsaOverlap.hEvent = hSendCompleted;

											char log[3000];
											int nResult;
/*
											bool prt_can_read=false, prt_can_write=false;

											fd_set read_fds, write_fds;

											FD_ZERO(&read_fds);
											FD_ZERO(&write_fds);

											FD_SET(port->Socket(), &read_fds);
											FD_SET(port->Socket(), &write_fds);

											// Check the status of both read and write sockets
											nResult = select(1, &read_fds, &write_fds, 0, &selectWaitTimeOut);
											if (nResult <= 0)
											{
												LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() select timed out."));
											}
											else
											{
												prt_can_read = FD_ISSET(port->Socket(), &read_fds)!=0;
												prt_can_write = FD_ISSET(port->Socket(), &write_fds)!=0;
											}

											if (!prt_can_write)
											{
													LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Localhost socket has some problem."));
													_snprintf(log, sizeof(log)/sizeof(log[0]), "%s", wsaBuffer.buf);
													LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() WSASend() will probably fail after sending this data: ") + _bstr_t(log));
											}
*/
											nResult = WSASend(port->Socket(), &wsaBuffer, 1, &dwIterBytesSent, 0L, &wsaOverlap, NULL);

											if (nResult==SOCKET_ERROR)
											{
												DWORD dwError = ::WSAGetLastError();

												if (dwError == WSA_IO_PENDING)
                                                {
													//LLOGDEBUG(_T("KodakSecureTunnel::SSL_IO_Loop() WSASend() returned WSA_IO_PENDING"));
                                                    DWORD dwBufferSendCount = 10L;
                                                    DWORD dwFlags = 0L;
                                                    while (dwBufferSendCount > 0)
                                                    {
                                                        ::WaitForSingleObject(hSendCompleted, 100);
                                                        if (::WSAGetOverlappedResult(port->Socket(), &wsaOverlap, &dwIterBytesSent, FALSE, &dwFlags))
                                                        {
                                                            dwBytesSent += dwIterBytesSent;
															sslReadBuffer.len -= dwIterBytesSent;
															if (!sslReadBuffer.Empty())
															{
																//LLOGTRACE(_T("KodakSecureTunnel::SSL_IO_Loop() Got a partial send to the LocalHost port"));
															}
															else
															{
		                                                        //LLOGTRACE(_T("KodakSecureTunnel::SSL_IO_Loop() Successfully sent to localhost port"));
															}
                                                            break;
                                                        }
                                                        else
														{
															dwError = ::WSAGetLastError();
															if ((dwError == WSA_IO_INCOMPLETE) || (dwError == WSA_IO_PENDING))
															{
																//LLOGTRACE(_T("KodakSecureTunnel::SSL_IO_Loop() Waiting to send to localhost"));
															}
															else
															{
																LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Failed to send to localhost (error=") + to_bstr_t(dwError,16) + _T(")"));
																break;
															}
														}
                                                        --dwBufferSendCount;
                                                    }
                                                    if (dwBufferSendCount == 0)
                                                    {
														//	On WinNT4 and Win98 even though socket appears to be blocked it transfers data anyway
														//	So, we assume here that the entire buffer was transfered
														dwIterBytesSent = sslReadBuffer.len;
                                                        dwBytesSent += dwIterBytesSent;
														sslReadBuffer.len -= dwIterBytesSent;
														//_snprintf(log, sizeof(log)/sizeof(log[0]), "%s", wsaBuffer.buf);
														//LLOGDEBUG(_T("KodakSecureTunnel::SSL_IO_Loop() Assuming that this data was sent anyway: ") + _bstr_t(log) );
                                                    }
                                                }
                                                else
                                                {
													LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() WSASend() failed (error=") + _bstr_t(log));
												    dwBytesSent = 0;
                                                }

												if (dwBytesSent==0)
												{
													_snprintf(log, sizeof(log)/sizeof(log[0]), "%s", wsaBuffer.buf);
													LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Failed while/after sending this data: ") + _bstr_t(log));
												}
  											}
											else
											{
                                                dwBytesSent += dwIterBytesSent;
												sslReadBuffer.len -= dwIterBytesSent;
												if (!sslReadBuffer.Empty())
												{
													//LLOGTRACE(_T("KodakSecureTunnel::SSL_IO_Loop() Got a partial send to the LocalHost port"));
												}
												else
												{
		                                            //LLOGTRACE(_T("KodakSecureTunnel::SSL_IO_Loop() Successfully sent to localhost port"));
												}
                                            }

		                                    ::CloseHandle(hSendCompleted);

											if (dwBytesSent == 0)
											{
												// An error occurred. Drop the port and break the loop.
												port->PrintPortMessage("SecureTunnel::SSL_IO_Loop() Error sending to localhost");
												port->PushBufferToSend(port->pSocketData(), 0L);
												port->FinishedSending();
												port->Deactivate();
												break;
											}
									    }
                                    }
								}
                                else
                                {
                                    //an authenticator packet handled by the class
									// Debug output block
									if (!authChannel)
                                    {
										authChannel = GetPortInList(SP_AUTHENTIC_SIG, 0, -1, tunnelInstance.ssl);
										if (!authChannel)
											throw("SecureTunnel::SSL_IO_Loop() Failed to set up AUTHENTICATION port.\n",0);
									}
    								if (!HandleNullSocket(sessID, (const char*) sslReadBuffer.data, sslReadBuffer.len, authChannel))
    									sendMessages = 10;
    							}
								notAliveCtr = GetTickCount();// reset, since the other side is alive and sending
								}	// scope bracket
    							break;

    						case SSL_ERROR_ZERO_RETURN:
    							// connection closed 
   							    throw(SSL_ERROR_ZERO_RETURN);
								break;

    						case SSL_ERROR_WANT_READ:
    							// we need to retry the read later
    							read_waiton_read = 1;
    							break;

    						case SSL_ERROR_WANT_WRITE:
    							// we need to retry the read after we can write
    							read_waiton_write = 1;
    							break;

    						default:
                                {
									LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() SSL_Read failed due to a system error."));
   							        throw(-1);
                                }
    							break;
    						}							
					}
                    catch (...)
                    {
						LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Exception in READ block."));
						throw;
					}
    			}

                // WRITING
    			/* this "if" statement writes data. it will only be entered if
    			 * the following conditions are all true:
    			 * 1. we're not in the middle of a read
    			 * 2. there's data 
    			 * 3. either we need to read to complete a previously blocked write
    			 *    and now we can read, or we can write 
    			 *    regardless of whether we're blocking for availability to write
    			 */
                if (sslWriteBuffer.Empty())
                    PopBufferToSend(tunnelInstance.ssl, sslWriteBuffer);
    			if (!sslWriteBuffer.Empty())
                {
                    // don't do this if no writes
    				if (!(read_waiton_write || read_waiton_read) &&
    					(can_write || (can_read && write_waiton_read)))
    				{
                        try
                        {
                            if (bCaptureData)
                            {
								// Write the data to the capture file
                                if (!hWriteCapture)
                                {
                                    hWriteCapture = CreateFile("c:\\SecureLink Write Capture",
                                                     GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                                     FILE_ATTRIBUTE_NORMAL, NULL);
                                }
                                else
                                {
                                    DWORD dwBytesWritten;
                                    WriteFile(hWriteCapture, sslWriteBuffer.appsig,
                                        sslWriteBuffer.len, &dwBytesWritten, NULL);
                                }
                            }
							// clear the flags 
    						write_waiton_read = 0;
    						write_waiton_write = 0;
       						// perform the write from the start of the buffer 
    						code = SSL_write(tunnelInstance.ssl, sslWriteBuffer.appsig, sslWriteBuffer.len);
							switch (SSL_get_error(tunnelInstance.ssl, code))
    						{
    							case SSL_ERROR_NONE:
                                    // if len == 0, all done, else we will get it later
    								sslWriteBuffer.len -= code;
    								if (!sslWriteBuffer.Empty())
                                    {
                                        // if this was a partial write, move the data forward and
                                        // adjust the length value...
										// set debugging info string
										//LLOGTRACE(_T("KodakSecureTunnel::SSL_IO_Loop() Sent partial buffered data for ") + _bstr_t(sslWriteBuffer.appsig) + _T(" id:") + to_bstr_t(sslWriteBuffer.appPortID,10) + _T(" #") + to_bstr_t(sslWriteBuffer.connID,10) + _T(" SSL>") + _bstr_t(sslStrBuff));
										memmove(sslWriteBuffer.appsig, sslWriteBuffer.appsig + code, sslWriteBuffer.len);
									}
                                    //else
										//LLOGTRACE(_T("KodakSecureTunnel::SSL_IO_Loop() Sent buffered data for ") + _bstr_t(sslWriteBuffer.appsig) + _T(" id:") + to_bstr_t(sslWriteBuffer.appPortID,10) + _T(" #") + to_bstr_t(sslWriteBuffer.connID,10) + _T(" SSL>") + _bstr_t(sslStrBuff));
					                pingCtr = GetTickCount();
    								break;

    							case SSL_ERROR_ZERO_RETURN:
    								// connection closed 
    								throw(SSL_ERROR_ZERO_RETURN);

    							case SSL_ERROR_WANT_READ:
    								// we need to retry the write after we can read
    								write_waiton_read = 1;
    								break;

    							case SSL_ERROR_WANT_WRITE:
    								// we need to retry the write
    								write_waiton_write = 1;
    								break;

    							default:
                                    {
									    LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() SSL_Write failed due to a system error."));
   							            throw(-1);
                                    }
    							    break;
    						}
						}
                        catch (...)
                        {
							LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Exception in WRITE block."));
							throw;
						}
					}
                    //else
						//LLOGTRACE(_T("KodakSecureTunnel::SSL_IO_Loop() Nothing to send."));
    			}
                else if (!(read_waiton_write || read_waiton_read) &&
    				      (can_write || (can_read && write_waiton_read)))
                {		
                    // not waiting to read
                    // can write or, at least, not waiting on a read to write
    				// this block just reduces our processor time if nothing is pending
    				if ((GetTickCount() > pingCtr + SEND_ALIVE_TRIGGER))
                    {
						pingCtr = GetTickCount();
						if (authChannel)						
    						SendString(SEND_ALIVE, authChannel);													
						else
							LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Got a Send Stay Alive trigger without an AUTH channel."));						
    				}					
                    // Allow SSL time to process socket I/O.
					Sleep(SLEEPTIME);
                    // Clean up any inactive ports.
                    CullInactivePorts(tunnelInstance.ssl);					
    			}
            }
        }

    }
    catch (char* str)
    {
		LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Leaving because: ") + _bstr_t(str));
	}
    catch (...)
    {
		LLOGDEBUG(_T("SecureTunnel::SSL_IO_Loop() Leaving because of an unknown exception!"));		
	}
    try
    {
        if (hReadCapture)
            CloseHandle(hReadCapture);
        if (hWriteCapture)
            CloseHandle(hWriteCapture);		

        // Mark all remaining ports for this SSL instance for deletion.
	    DeactivateLocalPortsForSSL(tunnelInstance.ssl);
        // Now actually delete all of the ports.
        CullInactivePorts(tunnelInstance.ssl);
        // Remove the buffer queue associated with this instance.
	    DeleteBufferQueue(tunnelInstance.ssl);
        // Close the authenticator session.
	    SecureConnectionDown(sessID);
        // Close the SSL connection and set it back to blocking to simplify.
        SetBlocking(tunnelInstance.ssl, true);
        ERR_remove_state(GetCurrentThreadId());
        SSL_shutdown(tunnelInstance.ssl);
    }
    catch (...) {}
    _set_se_translator(pTranslator);
}