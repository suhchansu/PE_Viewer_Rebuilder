#include "system.h"

int main(int argc, char *argv[])
{
	Init init(argv[1]);
	InterfaceInit iInit;

	// 3�� Header, IAT, EAT �� ������ list[5] �ȿ� ����ִ�.
	for (int i = 0; i < 5; i++) {
		(list[i])->Set();
		(list[i])->Show();
	}
	return 0;
}
