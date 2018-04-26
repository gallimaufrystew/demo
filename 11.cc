
#include <unistd.h>
#include <stdio.h>
#include <time.h>

int main() {
 
    while (true) {
        time_t t1 = time(NULL);

	sleep(10);

        time_t t2 = time(NULL);
        
        printf("diff = %d\n", difftime(t1,t2));
        
    }

    return 0;
}
