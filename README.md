# keycloak-feishu-idp

Keycloak 飞书 授权登录插件

**内容详解 https://www.cnblogs.com/jinxin-c/articles/keycloak_dingtalk.html**

需要在飞书开发者后台添加以下权限，并且需要发布应用

- 以应用身份读取通讯录
- 获取部门基础信息
- 获取部门组织架构信息
- 获取用户基本信息
- 获取用户组织架构信息
- 获取用户性别
- 获取用户邮箱信息
- 获取用户手机号
- 获取用户 user ID



To build:
`mvn clean package`

To install the social dingtalk work one has to:

* Add the jar to the Keycloak server (create `providers` folder if needed):
  * `$ cp target/keycloak-services-social-feishu-{x.y.z}.jar _KEYCLOAK_HOME_/providers/` 

* Add config page templates to the Keycloak server:
  * `$ cp themes/base/admin/resources/partials/realm-identity-provider-feishu.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials/`
  * `$ cp themes/base/admin/resources/partials/realm-identity-provider-feishu-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials/`

-----------------------------------------------------------------
特殊说明:
=========================================================
> 1.适配 Keycloak 12.0.4 版本
>
> 2.适配飞书 API 2022/01/29


