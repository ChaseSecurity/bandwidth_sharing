主要是使用rsync命令来备份文件  


# 需要准备的事情

## 远程服务器：
1.安装rsync  
2.编辑/etc/rsyncd.conf文件

> uid = root  
> gid = root  
> use chroot = no  
> max connections = 200  
> timeout = 300  
> pid file = /var/run/rsyncd.pid  
> lock file = /var/run/rsync.lock  
> log file = /var/log/rsyncd.log  
> read only = false  
> list = false  
> hosts allow = 0.0.0.0/0  
> #hosts deny = 0.0.0.0/32  
> auth users = root  
> secrets file = /etc/rsync.passwd  
> [backup]  
> path = /home/hrh/bandwidth_sharing/traffic_capture_scripts/  

uid和gid就是rsync使用的真实用户    
auth users 是虚拟用户，用于rsync命令，我图省事就也弄成一样了  
secrets file 是保存虚拟用户信息的地方，格式是user:password，权限是600  
[backup]是模块名，path是该模块的真实地址  

注意：rsyncd.conf文件不要有解释，一旦某行出现#，该行就失效了  

3.编辑/etc/rsync.passwd,输入user:password格式的信息，user是前面的auth users，然后更改文件权限为600  

4.在服务器创建ssh密钥对，主要是用来删除过期的文件的  

5.打开873端口  

6.运行如下指令  
> rsync --daemon 

7.（optional）加入开机自启动  
> echo "/usr/bin/rsync --damon" >>/etc/rc.local



## 本地服务器
1.在/etc/rsync.password中输入之前的password(暂时设置为123456），并设置权限600  

2.vi backup_time_machine_data.bash文件 

> src_dir_to_remove = ${src_dir_to_sync}/${provider}/${step_dir}

src_dir_to_sync 是远程服务器的模块名，src_dir_to_remove 就是远程要被同步的文件夹 

> backup_dir = $base_result_dir/${src_dir_to_sync}_${server}/${provider}/${step_dir}  

backup_dir 是本地保存备份的文件夹  

> real_path=${6:-"/home/hrh/bandwidth_sharing/traffic_capture_scripts/packetstream/traffic"}  

real_path 是远程服务器保存文件真实的路径，因为ssh不能使用rsync的模块名当作路径，得多这个步骤  

3.vi remote_server_file,格式是user@ip,user是之前的auth users  

4.将远程服务器的id_rsa放于该目录下  

## 在当前目录下要包含：  
1.backup_time_machine_data.bash 备份的脚本  
2.id_rsa 远程服务器账号的ssh_key  
3.remote_server_file 里面包含要备份的服务器信息，格式是user@ip  

# 开始备份
运行如下命令  
> bash backup_time_machine_data.bash  


# 测试运行结果（删除操作注释了）
![image](https://user-images.githubusercontent.com/57869555/184369478-2939a53f-cf49-422a-a6bd-49fd1b593d1c.png)
![image](https://user-images.githubusercontent.com/57869555/184369498-38b096df-de32-4cb7-bca7-0921bf0d5fd3.png)
![image](https://user-images.githubusercontent.com/57869555/184369518-e595b6b9-60da-47af-862a-d1e2e3f83cb1.png)
![image](https://user-images.githubusercontent.com/57869555/184369534-5c6c9049-e253-40d8-8c68-833eb2f8cfad.png)

    
