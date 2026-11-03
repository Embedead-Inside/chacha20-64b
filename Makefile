CC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -Wpedantic -Wconversion -O2

.PHONY: test clean
# アンロール版とコンパクト版の両方で、同一のテストを実行する
test:
	$(CC) $(CFLAGS) -o test/t_unrolled chacha20_64b.c test/test_chacha20_64b.c
	$(CC) $(CFLAGS) -DCHACHA20_64B_COMPACT -o test/t_compact chacha20_64b.c test/test_chacha20_64b.c
	./test/t_unrolled
	./test/t_compact

clean:
	rm -f test/t_unrolled test/t_compact
