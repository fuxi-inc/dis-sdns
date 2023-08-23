#!/bin/bash
set -x
#获取脚本所在的目录
workspace=$(cd $(dirname $0) && pwd -P)

#临时构建目录用于构建项目
tmpBuildPath="$workspace/temp_fuxi_build_dir"

export PATH=$GOROOT/bin:$GOPATH/bin:$PATH

# 添加go modules相关环境变量
export GOSUMDB=off
export GO111MODULE=on

echo "workspace=$workspace"
echo "tmpBuildPath=$tmpBuildPath"
echo "GOPATH=$GOPATH"

mkdir -p $tmpBuildPath/bin

module=dis-sdns
output="output"

#编译目标文件
go build -o $module
ret=$?
if [ $ret -ne 0 ];then
    echo "===== $module t pubuild failure ====="
    exit $ret
else
    echo -n "===== $module build successfully! ====="
fi


#cp ./${module} $workspace/
#cd $workspace

rm -rf $output
mkdir -p $output

# 填充output目录, output的内容即为待部署内容
(
    cp ./control.sh $output
    mv ${module} ${output} &&        		 # 移动需要部署的文件到output目录下
    echo -e "===== Generate output ok ====="
) || { echo -e "===== Generate output failure ====="; exit 2; } # 填充output目录失败后, 退出码为 非0

rm -fr $tmpBuildPath
