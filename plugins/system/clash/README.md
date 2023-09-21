# clash

## 下载

对应的地址：https://github.com/Dreamacro/clash/releases
目前最新版本是1.17.0，可以用。

## 运行

如果只是简单的使用，下载之后运行bin文件，然后再把配置文件改成自己服务商的配置即可。默认的配置目录在home目录下的~/.config/clash/

```bash
/home/solo/code/github/global_scripts/clash/bin/clash-linux-amd64-v1.17.0 -d /home/solo/code/github/global_scripts/clash/conf | tee /home/solo/code/github/global_scripts/clash/logs/logs.txt
```

在gs_system_clash.sh文件里已经写好了脚本，直接运行就可以。


## 开机自启动

配置一个服务，在/etc/systemd/system/下创建clash.service文件

```bash
sudo vim /etc/systemd/system/clash.service
```
把以下内容复制到clash.service
```bash
[Unit] 
Description=clash daemon
[Service] 
Type=simple 
User=root 
ExecStart=/home/solo/code/github/global_scripts/clash/bin/clash-linux-amd64-v1.17.0 -d /home/solo/code/github/global_scripts/clash/conf
Restart=on-failure  
[Install] 
WantedBy=multi-user.target
```
其中：ExecStart后面带上需要执行的脚本或者bin文件，这里多加-d /home/solo/code/github/global_scripts/clash/conf是因为我指定其配置文件在/home/solo/code/github/global_scripts/clash/conf目录。
最后通过systemctl命令reload服务，启用服务，启动服务即可。
```bash
sudo systemctl daemon-reload 
sudo systemctl enable clash
sudo systemctl start clash
sudo systemctl status clash
```

## 彩蛋
https://github.com/pojiezhiyuanjun/2023
