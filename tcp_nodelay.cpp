
    
    int on = 1;
    setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,(char *) &on,sizeof(int));
