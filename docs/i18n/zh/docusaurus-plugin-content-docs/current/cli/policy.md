---
title: infraguard policy
---

# infraguard policy

管理合规策略。

## 子命令

### list

列出所有可用策略：
```bash
infraguard policy list
```

### get

获取特定策略的详细信息：
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

更新策略库：
```bash
infraguard policy update
```

### validate

验证自定义策略：
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang zh
```

### format

格式化策略文件：
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

有关更多详细信息，请参阅[管理策略](../user-guide/managing-policies)。

