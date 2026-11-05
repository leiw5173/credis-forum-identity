# Credis Forum Identity

Discourse服务端插件：将通行证稳定UUID与论坛身份关联，提供签名开户/绑定及存活证明。与事件桥分别安装，不是主题或Discord机器人。

## 安装

论坛须有兼容的OAuth2 Basic认证器。本插件固定provider=`oauth2_basic`、论坛OAuth client_id=`discourse`；不要将积分OAuth客户端secret用于论坛客户端。

在自托管论坛`/var/discourse/containers/app.yml`已有`hooks.after_code`中追加，保留其他插件配置：

```yaml
hooks:
  after_code:
    - exec:
        cd: $home/plugins
        cmd:
          - git clone https://github.com/leiw5173/credis-forum-identity.git credis-forum-identity
          - git -C credis-forum-identity checkout --detach <APPROVED_PLUGIN_COMMIT>
```

`<APPROVED_PLUGIN_COMMIT>`替换为核准提交后再执行；平台文档提供参考组合，不要求版本号相同，勿直接部署默认分支最新代码。

仅首次安装或实际更新本插件时，论坛维护人在`/var/discourse`执行`./launcher rebuild app`。单容器切换/启动期间会暂时不可用，先备份并安排维护窗口。源码部署clone到Discourse的`plugins/credis-forum-identity`，按原安装流程构建、迁移及重启全部Web/worker。

## 配置

使用积分平台初始化生成的论坛包。将`app-env.yml`的env键值合并进论坛已有env块，把受保护文件只读挂到`/run/credis`；不要创建重复env块或提交真实接入材料。启用条件为`CREDIS_FORUM_IDENTITY_ENABLED=true`；可暂设false延后业务启用，需要时改true并重启相关进程。false不意味着插件代码/迁移完全不加载。

论坛OAuth接口与生成的`identity.json`须匹配；后台配置token POST、userinfo GET、send auth header启用，并关闭send auth body、debug auth、disable CSRF、allow association change和email verified。UUID取真实通行证响应，不用邮箱/用户名替代。

Puma必须原生验证客户端证书；普通Nginx终止TLS后转发证书Header不能替代。使用生成的Puma片段接入L4透传入口，身份接口再核URI SAN。论坛出站身份请求的`credits-ca.pem`当前只加载单张正确CA；不要放多根bundle或私钥，服务端提供完整中间链。

完整文件权限、双向TLS、OAuth及配套安装见[平台部署说明](https://github.com/leiw5173/SpacemitCredits/blob/docs/docker-deployment83-20261104/README.md)。安装不自动授予积分管理员或发布奖励规则。

## 维护与验证

平台与两个插件独立发布，仅要求身份、签名和接口合同兼容，不要求版本号相同或同步升级。**平台升级未改变论坛合同、插件代码或论坛配置时，无需更新、重启或重建论坛**；已有兼容插件可继续使用。主项目gitlink记录参考版本，不强制论坛跟随。只有插件、迁移、依赖或论坛配置需要变化时，才安排论坛侧操作；Discourse Core升级另核兼容性。

本仓库为身份插件唯一维护源；平台主项目的`discourse-auth-plugin/`子模块固定核准提交。更新前在兼容Core及隔离假数据论坛验证，不自动跟随主分支更新生产；网页更新器兼容尚未验收。

```sh
bundle exec rspec plugins/credis-forum-identity/spec
bundle exec rubocop plugins/credis-forum-identity
```

`test/`还含Ruby独立合同检查及Node绑定页检查。真实OAuth/mTLS须单独端到端验证，不能以组件测试替代。初始独立发布仅改变仓库组织和安装说明，签名、身份和迁移源码保持原样。
