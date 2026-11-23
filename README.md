伪造发件人的钓鱼邮件进了收件箱，域名的发件策略明明是拒绝：机制解析不区分大小写的要求未落实，机制名大小写混写后失效；逐机制求值不按顺序，后面的放行覆盖前面的失败；机制命中后继续求值，最终结果取最后一条；对齐判定用后缀比较，子域被当作对齐；宽松对齐不校验组织域，任意子域都算对齐；限定符缺失时默认通过，未声明即放行；查找次数不设上限，递归解析被放大；策略为无时按拒绝处理，正常邮件被误拒；策略校验不检查是否启用严格对齐；批量评估复用解析结果，后一封邮件命中前一封邮件的域名。mailauth/evaluate.py 是核心，tests/test_evaluate.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
在仓库根目录执行 pytest tests -q，预期输出 15 failed，并且没有 error。测试只依赖 pytest，运行前不需要启动服务，也不需要联网；若本机没有 pytest，先安装 pytest 再运行。首次运行即可复现 15 条红测试，修完 src/mailauth/evaluate.py 的 8 个桩后应全部通过。

字段表
领域 安全
类型 漏洞检测与攻防
任务 Bugfix
技术栈 Python 3, pytest
依赖 无外部依赖
难度 高

tests 不可修改
tests/conftest.py 与 tests/test_evaluate.py 是验收基准，解题时不得改动，也不得通过改测试来凑绿；只允许修改 src/mailauth/evaluate.py，把 8 个桩按顺序逐个实现。

src 布局
仓库采用 src 布局：包源码位于 src/mailauth，导入名是 mailauth，唯一实现文件是 src/mailauth/evaluate.py。tests/conftest.py 在收集测试前把 src 加入 sys.path，因此直接运行 pytest tests 即可导入，不需要安装包，也不需要额外环境变量。## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

