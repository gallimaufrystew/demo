

	int optVal = 16*1024;
	int optLen = sizeof(int);

	ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&optVal, optLen);
    if (ret == SOCKET_ERROR) {
        printf("setsockopt SO_SNDBUF error: %u\n", WSAGetLastError());
    }

	ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&optVal, &optLen);
	if (ret != SOCKET_ERROR) {
		printf("SockOpt Value: %ld\n", optVal);
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&optVal, optLen);
    if (ret == SOCKET_ERROR) {
        printf("setsockopt SO_SNDBUF error: %u\n", WSAGetLastError());
    }

	ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&optVal, &optLen);
	if (ret != SOCKET_ERROR) {
		printf("SockOpt Value: %ld\n", optVal);
	}
  
