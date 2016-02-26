#include "system.h"

int main(int argc, char *argv[])
{
	Init init(argv[1]);
	InterfaceInit iInit;

	// 3개 Header, IAT, EAT 의 정보가 list[5] 안에 들어있다.
	for (int i = 0; i < 5; i++) {
		(list[i])->Set();
		(list[i])->Show();
	}
	return 0;
}
