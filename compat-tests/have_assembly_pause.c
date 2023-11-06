#define cpu_relax() do { asm volatile("pause\n":::"memory"); } while (0)

int main(void)
{
	cpu_relax();

	return 0;
}
