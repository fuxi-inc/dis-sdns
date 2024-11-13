#!/bin/bash
set -x
workspace=$(cd $(dirname $0) && pwd -P)
cd ${workspace}
module=dis-sdns
app=${module}

#############################################
## main
## 以托管方式, 启动服务
## control.sh脚本, 必须实现start方法
#############################################

action=$1
hostname=`hostname`
echo "hostname: $hostname\n"


case ${action} in
    "start" )
      if [[ $hostname == "fxzk-prd-node3" ]]; then
          exec ./$app -config=sdns.conf
      elif [[ $hostname == "iZ9dpcnz15a4zgy578frvnZ" ]]; then
          exec ./$app -config=sdns.conf
      else
          exec ./$app -config=sdns.online.conf
      fi
    ;;
    * )
        # 非法命令, 已非0码退出
        echo "unknown command"
        exit 1
        ;;
esac
