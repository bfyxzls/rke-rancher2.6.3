https://blog.csdn.net/zhangpfly/article/details/107375966
https://www.cnblogs.com/lkj371/p/12856416.html
删除RKE之前安装的版本
docker stop $(docker ps -aq)
 
docker system prune -f
 
docker volume rm $(docker volume ls -q)
 
docker image rm $(docker image ls -q)
 
rm -rf /etc/ceph \
       /etc/cni \
       /etc/kubernetes \
       /opt/cni \
       /opt/rke \
       /run/secrets/kubernetes.io \
       /run/calico \
       /run/flannel \
       /var/lib/calico \
       /var/lib/etcd \
       /var/lib/cni \
       /var/lib/kubelet \
       /var/lib/rancher/rke/log \
       /var/log/containers \
       /var/log/pods \
       /var/run/calico 

RKE搭建k8s集群&Helm3安装Rancher2.5.8高可用
下图是从网上借鉴的：

RKE搭建k8s集群&Helm3安装Rancher2.5.8高可用_rancher rke
RKE搭建k8s集群
环境准备

    操作系统是： Linux version 5.4.0-65-generic (buildd@lcy01-amd64-018) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #73-Ubuntu SMP Mon Jan 18 17:25:17 UTC 2021

    docker版本：Docker version 20.10.7, build f0df350

   cpu 	内存 	ip
    4 	4 	X.X.40.17
    4 	4 	X.X.40.18
    4 	4 	X.X.40.18

Docker安装
首先安装docker

//更新yum
yum clean all
yum repolist

//安装docker
//创建文件夹用于存放资源包
mkdir pkg

//开始下载docker，一共安装三个文件docker-ce、docker-ce-cli、containerd.io
wget --no-check-certificate https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/centos/7.9/x86_64/stable/Packages/docker-ce-19.03.4-3.el7.x86_64.rpm
wget --no-check-certificate https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/centos/7.9/x86_64/stable/Packages/docker-ce-cli-19.03.4-3.el7.x86_64.rpm
yum install *.rpm
//会提示报错
错误：软件包：3:docker-ce-19.03.4-3.el7.x86_64 (/docker-ce-19.03.4-3.el7.x86_64)
          需要：containerd.io >= 1.2.2-3
//按照要求下载container版本
wget --no-check-certificate https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/centos/7.9/x86_64/stable/Packages/containerd.io-1.2.4-3.1.el7.x86_64.rpm
yum install *.rpm

  检测是否安装成功
    docker version
    systemctl start docker
    systemctl status docker

    配置docker镜像源
    vi  /etc/docker/daemon.json
    {
    	"registry-mirrors": [
    	"https://jy43gu19.mirror.aliyuncs.com",
    	"https://registry.docker-cn.com",
        "https://reg-mirror.qiniu.com",
        "http://hub-mirror.c.163.com",
        "https://docker.mirrors.ustc.edu.cn"
    	]
    }

   设置开机自启 systemctl enable docker
关闭Selinux
//设置 SELINUX=disabled，重启后永久关闭
vi /etc/sysconfig/selinux
//设置暂时关闭
setenforce 0
getenforce


设置IPV4转发
vi /etc/sysctl.conf
//增加
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1

//执行如下命令生效，
sysctl -p


如果出现下面报错“
net.ipv4.ip_forward = 1
sysctl: cannot stat /proc/sys/net/bridge/bridge-nf-call-ip6tables: No such file or directory 
sysctl: cannot stat /proc/sys/net/bridge/bridge-nf-call-iptables: No such file or directory
执行
modprobe br_netfilter 
sysctl -p


关闭防火墙
systemctl stop firewalld
systemctl disable firewalld

(1) 永久禁用swap
可以直接修改
vi /etc/fstab文件，注释掉swap项
(2) 临时禁用
 swapoff -a
启动cgroup
vi /etc/default/grub
//修改参数
GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"
//增加参数
GRUB_CMDLINE_LINUX_DEFAULT="cgroup_enable=memory swapaccount=1"
运行下面命令使得上面设置生效
grub2-mkconfig -o /boot/grub2/grub.cfg

配置hosts和hostname
$ sudo hostnamectl set-hostname node1
$ sudo hostnamectl set-hostname node2
$ sudo hostnamectl set-hostname node3

$ cat > /etc/hosts << EOF
192.168.1.156 node1
192.168.1.167 node2
192.168.1.168 node3
EOF

RKE安装

下载包(执行服务ip:X.X.40.17)
# wget https://github.com/rancher/rke/releases/download/v1.2.8/rke_linux-amd64
# mv rke_linux-amd64 /usr/local/bin/rke && chmod +x /usr/local/bin/rke

创建用户(执行服务ip:X.X.40.17,X.X.40.18,X.X.40.19)
useradd vonechain -g docker
echo "abcd1234@@" | passwd --stdin  vonechain

# usermod -a -G docker vonechain
#  sudo gpasswd -a vonechain  docker

K8s集群安装
SSH免密(执行服务ip:X.X.40.17,X.X.40.18,X.X.40.19)
#su  vonechain
# ssh-keygen

传输公钥（执行服务器ip:X.X.140.17 ）：
su  vonechain
ssh-copy-id  vonechain@192.168.0.204
本机也需要上传，不然在k8s创建集群时会报下面告警【Failed to set up SSH tunneling for host [192.168.0.204]: Can't retrieve Docker Info: error during connect: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/info": Unable to access node with address [192.168.0.204:22] using SSH. Please check if you are able to SSH to the node using the specified SSH Private Key and if you have configured the correct SSH username. Error: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain
】
ssh-copy-id  vonechain@X.X.140.18
ssh-copy-id  vonechain@X.X.140.19



传输公钥（执行服务器ip:X.X.140.18）
su - vonechain
ssh-copy-id X.X.40.17
ssh-copy-id X.X.40.19

传输公钥（执行服务器ip:X.X.140.19）
su - vonechain
ssh-copy-id X.X.40.18
ssh-copy-id X.X.40.17

编写rancher-cluster.yml（执行服务器ip:X.X.140.17 ）：
# cat rancher-cluster.yml 
nodes:
  - address: X.X.40.17
    internal_address: X.X.40.17
    user: vonechain
    role: [controlplane,worker,etcd]
  - address: X.X.40.18
    internal_address: X.X.40.18
    user: vonechain
    role: [controlplane,worker,etcd]
  - address: X.X.40.19
    internal_address: X.X.40.19
    user: vonechain
    role: [controlplane,worker,etcd]

services:
    etcd:
      snapshot: true
      creation: 6h
      retention: 24h


执行RKE，安装k8s集群（执行服务器ip:X.X.140.17 ）：
rke up --config ./rancher-cluster.yml

报错解决
1 /var/run/docker权限问题；需要将本账户加入到docker组即可
2 2379端口的etcd无法连接，签名不对问题，verify client's certificate: x509: certificate signed by ；解决方法
docker stop $(docker ps -aq)
docker system prune -f
docker volume rm $(docker volume ls -q)

for mount in $(mount | grep tmpfs | grep '/var/lib/kubelet' | awk '{ print $3 }') /var/lib/kubelet /var/lib/rancher; do umount $mount; done

rm -rf /etc/ceph \
       /etc/cni \
       /etc/kubernetes \
       /opt/cni \
       /opt/rke \
       /run/secrets/kubernetes.io \
       /run/calico \
       /run/flannel \
       /var/lib/calico \
       /var/lib/etcd \
       /var/lib/cni \
       /var/lib/kubelet \
       /var/lib/rancher/rke/log \
       /var/log/containers \
       /var/log/pods \
       /var/run/calico

rke remove --config rancher-cluster.yml


设置环境变量（执行服务器ip:X.X.140.17 ）：
su  vonechain
vi .bashrc
添加：export KUBECONFIG=/home/vonechain/kube_config_rancher-cluster.yml
source .bashrc






安装Kubectl（执行服务器ip:X.X.140.17 ）：

切到root账户
# curl -s https://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg| sudo apt-key add –

# cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
deb http://mirrors.ustc.edu.cn/kubernetes/apt kubernetes-xenial main
EOF

# apt-get update
# apt-get install -y kubectl

检查k8s集群（执行服务器ip:X.X.140.17 ）：
su  vonechain
kubectl get nodes

k8s集群安装完成！
Helm3安装Rancher2.5.8高可用
安装Helm3

下载安装helm3(执行服务器IP：X.X.40.17):

切到root账户
# wget -c https://get.helm.sh/helm-v3.6.2-linux-amd64.tar.gz
# tar zxvf helm-v3.6.2-linux-amd64.tar.gz
# mv /home/vonechain/linux-amd64/helm /usr/local/bin/helm && chmod +x /usr/local/bin/helm
# helm version
Helm3安装Rancher最新版集群

以下操作全部都是在X.X.40.17服务器上执行。
使用helm repo add命令添加Rancher chart仓库地址
su  vonechain
helm repo add rancher-stable https://releases.rancher.com/server-charts/stable

生成自签证书

bash  key.sh  --ssl-size=2048 --ssl-date=3650

 域名就是默认的：local.rancher.com。

看看key.sh里面是什么，脚本不多介绍了：
#!/bin/bash -e

help ()
{
    echo  ' ================================================================ '
    echo  ' --ssl-domain: 生成ssl证书需要的主域名，如不指定则默认为local.rancher.com，如果是ip访问服务，则可忽略；'
    echo  ' --ssl-trusted-ip: 一般ssl证书只信任域名的访问请求，有时候需要使用ip去访问server，那么需要给ssl证书添加扩展IP，多个IP用逗号隔开；'
    echo  ' --ssl-trusted-domain: 如果想多个域名访问，则添加扩展域名（SSL_TRUSTED_DOMAIN）,多个扩展域名用逗号隔开；'
    echo  ' --ssl-size: ssl加密位数，默认2048；'
    echo  ' --ssl-date: ssl有效期，默认10年；'
    echo  ' --ca-date: ca有效期，默认10年；'
    echo  ' --ssl-cn: 国家代码(2个字母的代号),默认CN;'
    echo  ' 使用示例:'
    echo  ' ./create_self-signed-cert.sh --ssl-domain=www.test.com --ssl-trusted-domain=www.test2.com \ '
    echo  ' --ssl-trusted-ip=1.1.1.1,2.2.2.2,3.3.3.3 --ssl-size=2048 --ssl-date=3650'
    echo  ' ================================================================'
}

case "$1" in
    -h|--help) help; exit;;
esac

if [[ $1 == '' ]];then
    help;
    exit;
fi

CMDOPTS="$*"
for OPTS in $CMDOPTS;
do
    key=$(echo ${OPTS} | awk -F"=" '{print $1}' )
    value=$(echo ${OPTS} | awk -F"=" '{print $2}' )
    case "$key" in
        --ssl-domain) SSL_DOMAIN=$value ;;
        --ssl-trusted-ip) SSL_TRUSTED_IP=$value ;;
        --ssl-trusted-domain) SSL_TRUSTED_DOMAIN=$value ;;
        --ssl-size) SSL_SIZE=$value ;;
        --ssl-date) SSL_DATE=$value ;;
        --ca-date) CA_DATE=$value ;;
        --ssl-cn) CN=$value ;;
    esac
done

# CA相关配置
CA_DATE=${CA_DATE:-3650}
CA_KEY=${CA_KEY:-cakey.pem}
CA_CERT=${CA_CERT:-cacerts.pem}
CA_DOMAIN=cattle-ca

# ssl相关配置
SSL_CONFIG=${SSL_CONFIG:-$PWD/openssl.cnf}
SSL_DOMAIN=${SSL_DOMAIN:-'local.rancher.com'}
SSL_DATE=${SSL_DATE:-3650}
SSL_SIZE=${SSL_SIZE:-2048}

## 国家代码(2个字母的代号),默认CN;
CN=${CN:-CN}

SSL_KEY=$SSL_DOMAIN.key
SSL_CSR=$SSL_DOMAIN.csr
SSL_CERT=$SSL_DOMAIN.crt

echo -e "\033[32m ---------------------------- \033[0m"
echo -e "\033[32m       | 生成 SSL Cert |       \033[0m"
echo -e "\033[32m ---------------------------- \033[0m"

if [[ -e ./${CA_KEY} ]]; then
    echo -e "\033[32m ====> 1. 发现已存在CA私钥，备份"${CA_KEY}"为"${CA_KEY}"-bak，然后重新创建 \033[0m"
    mv ${CA_KEY} "${CA_KEY}"-bak
    openssl genrsa -out ${CA_KEY} ${SSL_SIZE}
else
    echo -e "\033[32m ====> 1. 生成新的CA私钥 ${CA_KEY} \033[0m"
    openssl genrsa -out ${CA_KEY} ${SSL_SIZE}
fi

if [[ -e ./${CA_CERT} ]]; then
    echo -e "\033[32m ====> 2. 发现已存在CA证书，先备份"${CA_CERT}"为"${CA_CERT}"-bak，然后重新创建 \033[0m"
    mv ${CA_CERT} "${CA_CERT}"-bak
    openssl req -x509 -sha256 -new -nodes -key ${CA_KEY} -days ${CA_DATE} -out ${CA_CERT} -subj "/C=${CN}/CN=${CA_DOMAIN}"
else
    echo -e "\033[32m ====> 2. 生成新的CA证书 ${CA_CERT} \033[0m"
    openssl req -x509 -sha256 -new -nodes -key ${CA_KEY} -days ${CA_DATE} -out ${CA_CERT} -subj "/C=${CN}/CN=${CA_DOMAIN}"
fi

echo -e "\033[32m ====> 3. 生成Openssl配置文件 ${SSL_CONFIG} \033[0m"
cat > ${SSL_CONFIG} <<EOM
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
EOM

if [[ -n ${SSL_TRUSTED_IP} || -n ${SSL_TRUSTED_DOMAIN} ]]; then
    cat >> ${SSL_CONFIG} <<EOM
subjectAltName = @alt_names
[alt_names]
EOM
    IFS=","
    dns=(${SSL_TRUSTED_DOMAIN})
    dns+=(${SSL_DOMAIN})
    for i in "${!dns[@]}"; do
      echo DNS.$((i+1)) = ${dns[$i]} >> ${SSL_CONFIG}
    done

    if [[ -n ${SSL_TRUSTED_IP} ]]; then
        ip=(${SSL_TRUSTED_IP})
        for i in "${!ip[@]}"; do
          echo IP.$((i+1)) = ${ip[$i]} >> ${SSL_CONFIG}
        done
    fi
fi

echo -e "\033[32m ====> 4. 生成服务SSL KEY ${SSL_KEY} \033[0m"
openssl genrsa -out ${SSL_KEY} ${SSL_SIZE}

echo -e "\033[32m ====> 5. 生成服务SSL CSR ${SSL_CSR} \033[0m"
openssl req -sha256 -new -key ${SSL_KEY} -out ${SSL_CSR} -subj "/C=${CN}/CN=${SSL_DOMAIN}" -config ${SSL_CONFIG}

echo -e "\033[32m ====> 6. 生成服务SSL CERT ${SSL_CERT} \033[0m"
openssl x509 -sha256 -req -in ${SSL_CSR} -CA ${CA_CERT} \
    -CAkey ${CA_KEY} -CAcreateserial -out ${SSL_CERT} \
    -days ${SSL_DATE} -extensions v3_req \
    -extfile ${SSL_CONFIG}

echo -e "\033[32m ====> 7. 证书制作完成 \033[0m"
echo
echo -e "\033[32m ====> 8. 以YAML格式输出结果 \033[0m"
echo "----------------------------------------------------------"
echo "ca_key: |"
cat $CA_KEY | sed 's/^/  /'
echo
echo "ca_cert: |"
cat $CA_CERT | sed 's/^/  /'
echo
echo "ssl_key: |"
cat $SSL_KEY | sed 's/^/  /'
echo
echo "ssl_csr: |"
cat $SSL_CSR | sed 's/^/  /'
echo
echo "ssl_cert: |"
cat $SSL_CERT | sed 's/^/  /'
echo

echo -e "\033[32m ====> 9. 附加CA证书到Cert文件 \033[0m"
cat ${CA_CERT} >> ${SSL_CERT}
echo "ssl_cert: |"
cat $SSL_CERT | sed 's/^/  /'
echo

echo -e "\033[32m ====> 10. 重命名服务证书 \033[0m"
echo "cp ${SSL_DOMAIN}.key tls.key"
cp ${SSL_DOMAIN}.key tls.key
echo "cp ${SSL_DOMAIN}.crt tls.crt"
cp ${SSL_DOMAIN}.crt tls.crt



创建 rancher 的 namespace

kubectl --kubeconfig=$KUBECONFIG     create namespace cattle-system

helm 渲染中 --set privateCA=true 用到的证书

kubectl -n cattle-system create secret generic tls-ca --from-file=cacerts.pem

helm 渲染中 --set additionalTrustedCAs=true 用到的证书

cp cacerts.pem ca-additional.pem
kubectl -n cattle-system create secret generic tls-ca-additional --from-file=ca-additional.pem

helm 渲染中 --set ingress.tls.source=secret 用到的证书和密钥

kubectl -n cattle-system create secret tls tls-rancher-ingress --cert=tls.crt --key=tls.key

通过Helm将部署模板下载到本地：
helm search repo rancher-stable 
helm fetch rancher-stable/rancher
当前目录会多一个rancher-2.5.8.tgz，目前最新版是2.6.3，如果还希望下载老版本，需要手动下载了

使用以下命令渲染模板：

helm template rancher ./rancher-2.5.8.tgz \
     --namespace cattle-system --output-dir . \
     --set privateCA=true \
     --set additionalTrustedCAs=true \
     --set ingress.tls.source=secret \
     --set hostname=local.rancher.com \
     --set useBundledSystemChart=true


在rancher目录中可以看到渲染好的模板文件：
RKE搭建k8s集群&Helm3安装Rancher2.5.8高可用_rancher rke_09

使用kubectl安装rancher

kubectl -n cattle-system apply -R -f ./rancher/templates/

执行结果：
RKE搭建k8s集群&Helm3安装Rancher2.5.8高可用_rancher rke_10

在执行结果中有个告警：Warning: networking.k8s.io/v1beta1 Ingress is deprecated in v1.19+, unavailable in v1.22+; use networking.k8s.io/v1 Ingress
这个时，我们需要去修改ingress.yaml，不然服务会有问题
RKE搭建k8s集群&Helm3安装Rancher2.5.8高可用_rancher rke_11
修改文件请参考官方文档：

    Kubernetes version 1.20+ introduces the networking.k8s.io API version as stable. If you have ingresses that predate K3S 1.20, you have until Kubernetes 1.22 to update them. Until then, if you use old-style ingress definitions, you will receive a warning like Warning: networking.k8s.io/v1beta1 Ingress is deprecated in v1.19+, unavailable in v1.22+; use networking.k8s.io/v1 Ingress when you apply the ingress to a cluster.

变化：

spec.backend -> spec.defaultBackend
serviceName -> service.name
servicePort -> service.port.name (for string values)
servicePort -> service.port.number (for numeric values)
pathType no longer has a default value in v1; Exact, Prefix, or ImplementationSpecific must be specified for each.


修改好后将ingress删除再启动：

cd /home/vonechain/rancher/templates
kubectl -n cattle-system delete -R -f ingress.yaml 
kubectl -n cattle-system apply -R -f ingress.yaml

检查安装进度：
这个安装过程，根据计算机配置需要一点时间的

kubectl -n cattle-system get all

客户端配置hosts

可以访问了



到此，我们已经安装完了！


# 升级
3 - RKE HA升级

    注意此方法仅适用于Rancher:v2.0.8及之前的版本

一、先决条件

从v2.0.7开始，Rancher引入了system项目，该项目是自动创建的，用于存储Kubernetes需要运行的重要命名空间。在升级到v2.0.7+前，请检查环境中有没有创建system项目，如果有则删除。并检查确认所有系统命名空间未分配到任何项目下，如果有则移到出去，以防止集群网络问题。

    Rancher Kubernetes Engine v0.1.7或更高版本

etcd快照功能仅在RKE v0.1.7及更高版本中可用

    保证所有ETCD节点具有相同的快照版本

# kubectl安装

在主机或者远程访问的笔记本上安装kubectl命令行工具

    rancher-cluster.yml(RKE配置文件)

通过RKE创建kubernetes集群，需要预先设置rancher-cluster.yml配置文件，通过这个配置文件安装kubernetes集群，这个文件需要与RKE二进制文件存放同一目录。

    确认系统存在以下路径:~/.kube/，如果没有，请自行创建。

    kube_config_rancher-cluster.yml(kubectl配置文件)

RKE安装kubernetes集群后，会在RKE二进制文件相同目录下生成kube_config_rancher-cluster.yml文件，复制该配置文件到~/.kube/目录.
# 升级步骤

    在安装了kubectl命令行工具的电脑上打开终端

    切换路径到RKE二进制文件所在目录，确认rancher-cluster.yml在同一路径下

    创建ETCD快照备份

替换<SNAPSHOT.db>为您喜欢的快照名称(例如upgrade.db)
```
# MacOS
./rke_darwin-amd64 etcd snapshot-save --name <SNAPSHOT.db> --config rancher-cluster.yml
# Linux
./rke_linux-amd64 etcd snapshot-save --name <SNAPSHOT.db> --config rancher-cluster.yml
```
 RKE获取每个etcd节点上的运行快照，保存快照文件当前到etcd节点的/opt/rke/etcd-snapshots目录下.

# Rancher 升级

输入以下命令进行升级，注意升级的代码根据版本的不同，可以有所不同:
```
kubectl --kubeconfig=kube_config_rancher-cluster.yml set image deployment/cattle cattle-server=rancher/rancher:<VERSION_TAG> -n cattle-system

# rancher v2.5.8的升级到2.6.3如下
kubectl --kubeconfig=kube_config_rancher-cluster.yml set image deployment/rancher rancher=rancher/rancher:v2.6.3 -n cattle-system

```

替换<VERSION_TAG>为想要升级到的版本，可用的镜像版本可查阅[DockerHub](https://hub.docker.com/r/rancher/rancher/tags/)。

> 说明：set image用来更新镜像，上面的代码更新Deployment类型下面的cattle部署项目，容器是cattle-server,更新一个新的镜像。

```
# deployment/rancher表示deployment下面name为rancher的项目，第二个rancher=rancher/rancher:v2.6.3表示容器名称为rancher，它的镜像为rancher/rancher:v2.6.3

kubectl --kubeconfig=kube_config_rancher-cluster.yml set image deployment/rancher rancher=rancher/rancher:v2.6.3 -n cattle-system
```
请勿使用后缀为rc或者为master的镜像，具体详情请查看版本标签。

登录Rancher UI,通过检查浏览器窗口左下角显示的版本，确认是否升级成功。