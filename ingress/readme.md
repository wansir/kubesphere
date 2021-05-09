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

此时能正常创建网关到namespace中，下面的操作为代码的逻辑，无需手动操作：

1. 检查是否存在`clusterrole (system:kubesphere-router-clusterrole)`，如果不存在则重新创建；
2. 检查是否存在 `clusterrolebinding (system:nginx-ingress-clusterrole-binding)`， 如果不存在重新创建；
3. 多个ns时，在clusterrolebindings的subjects中添加新的ns，如：

```bash
kubectl get clusterrolebindings.rbac.authorization.k8s.io system:nginx-ingress-clusterrole-binding -oyaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    kubernetes.io/created-by: kubesphere.io/ks-router
  creationTimestamp: "2021-05-09T07:05:17Z"
  name: system:nginx-ingress-clusterrole-binding
  resourceVersion: "6245782"
  selfLink: /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system%3Anginx-ingress-clusterrole-binding
  uid: 568d4011-7df9-4535-9357-e2248063593a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kubesphere-router-clusterrole
subjects:
- kind: ServiceAccount
  name: kubesphere-router-serviceaccount
  namespace: xx
- kind: ServiceAccount
  name: kubesphere-router-serviceaccount
  namespace: test1
```

4. 删除时，只会只会删除clusterrolebindings中的namespace相关的subject。
