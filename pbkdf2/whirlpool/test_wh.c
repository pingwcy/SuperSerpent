#include <stdio.h>
#include <string.h>
#include "whirlpool.h"

void print_hash(const unsigned char *hash, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
}

int main() {
    // 测试输入数据
    const char *test_string = "Hello, Whirlpool!";
    unsigned char hash_output[64];
    WHIRLPOOL_CTX ctx;

    // 初始化 Whirlpool 上下文
    WHIRLPOOL_init(&ctx);
    
    // 处理输入数据
    WHIRLPOOL_add((const unsigned char *)test_string, strlen(test_string), &ctx);
    
    // 计算最终哈希值
    WHIRLPOOL_finalize(&ctx, hash_output);
    
    // 打印哈希值
    printf("Whirlpool Hash of '%s':\n", test_string);
    print_hash(hash_output, sizeof(hash_output));

    return 0;
}