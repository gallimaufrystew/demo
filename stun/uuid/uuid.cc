
#include <windows.h>
#include <string>
#include <iostream>

/// UuidCreate - Minimum supported OS Win 2000
#pragma comment(lib, "rpcrt4.lib")


namespace win {
	namespace machine {

		class uuid
		{
		public:

			uuid() {}
			~uuid() {
				RpcStringFreeA((RPC_CSTR*)&str);
			}

			std::string get() {
				UuidCreate(&wuid);
				UuidToStringA(&wuid, (RPC_CSTR*)&str);
				return std::string(str);
			}

		private:

			char *str;
			UUID  wuid;
		};
	}
}

int main()
{
	for (int i = 0; i < 10000; ++i) {
		win::machine::uuid temp;
		std::cout << temp.get() << "\n";
	}

	for (;; ) {}

	return 0;
}

