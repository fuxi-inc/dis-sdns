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
      if [[ $hostname == "DISQtest" ]]; then
          exec ./$app -c ./conf/dev
      elif [[ $hostname == "iZ9dpcnz15a4zgy578frvnZ" ]]; then
          exec ./$app -c ./conf/pp
      else
          exec ./$app -c ./conf/online
      fi
    ;;
    * )
        # 非法命令, 已非0码退出
        echo "unknown command"
        exit 1
        ;;
esac
