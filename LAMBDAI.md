#

## 可以重写的模块

1. get_semantics.py

2. tofino_test_template.py

3. validate_p4_translation.py

## 示例运行流程

1.准备测试文件

```bash
# 生成不同架构的测试程序
./modules/p4c/build/p4bludgeon --output test_top.p4 --arch top
./modules/p4c/build/p4bludgeon --output test_v1model.p4 --arch v1model
./modules/p4c/build/p4bludgeon --output test_top2.p4 --arch top --seed 12345
```

2.直接测试src/下脚本

```bash
python3 src/get_semantics.py -i test_top.p4
python3 src/check_p4_pair.py --progs test_top.p4 test_top2.p4
python3 src/validate_p4_translation.py -i test_top.p4
python3 src/generate_p4_test.py -i test_v1model.p4 -r
python3 src/check_random_progs.py -i 1
```
