## 将网关部署到namespace操作方法


操作前，如果有项目已经开启网关，请先删除网关。

## **更新configmap**

```bash
kubectl -n kubesphere-system delete cm ks-router-config
kubectl -n kubesphere-system create cm ks-router-config --from-file cm/
```

## **更新ks-apiserver镜像**

**适用于ks3.0版本**

**如果是ks3.1版本，需要`kubectl -n kubesphere-system edit cc ` 开启redis**


下面的操作为通用操作

更新镜像：

```
kubectl -n kubesphere-system set image deploy/ks-apiserver ks-apiserver=zackzhangkai/ks-apiserver:release-3.0-refactor-nginx-ingress
```

## 最后

此时能正常创建网关到namespace中。

会同时创建role(system:kubesphere-router-role) rolebinding(nginx-ingress-role-nisa-binding) sa(kubesphere-router-serviceaccount)

删除网关时，该三个资源会一并删除。




