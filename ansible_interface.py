# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import os
import logging
from collections import namedtuple
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
from ansible.inventory.manager import InventoryManager
from ansible.inventory.host import Host,Group
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.executor.playbook_executor import PlaybookExecutor
from multiprocessing import current_process
from ansible.plugins.callback import CallbackBase

logger = logging.getLogger("automation")

class AnsibleAPI(object):
    """
    This is a General object for parallel execute modules.
    """

    def __init__(self, resource, resource_list, *args, **kwargs):
        self.resource = resource
        self.resource_list = resource_list
        self.inventory = None
        self.variable_manager = None
        self.loader = None
        self.options = None
        self.passwords = None
        self.callback = None
        self.args = args
        self.kwargs = kwargs
        self.__initializeData()
        self.results_raw = {}

    def __initializeData(self):
        """
        初始化ansible
        """
        current_process()._config = {'semprefix': '/mp'}
        Options = namedtuple('Options',
                             ['connection',
                              'remote_user',
                              'ask_sudo_pass',
                              'verbosity',
                              'ack_pass',
                              'module_path',
                              'forks',
                              'become',
                              'become_method',
                              'become_user',
                              'check',
                              'listhosts',
                              'listtasks',
                              'listtags',
                              'syntax',
                              'sudo_user',
                              'sudo',
                              'diff',
                              ])
        self.options = Options(connection='smart',
                               remote_user=None,
                               ack_pass=False,
                               sudo_user=None,
                               forks=10,
                               sudo=None,
                               ask_sudo_pass=False,
                               verbosity=5,
                               module_path=None,
                               become=None,
                               become_method=None,
                               become_user=None,
                               check=False,
                               diff=False,
                               listhosts=None,
                               listtasks=None,
                               listtags=None,
                               syntax=None,
                               # 跳板机的配置项
                               )

        '''
        Options = namedtuple('Options',
                             ['connection', 'module_path', 'forks', 'become', 'become_method', 'become_user', 'check',
                              'diff'])
        self.options = Options(connection='ssh', module_path='/path/to/mymodules', forks=100, become=None,
                               become_method=None, become_user=None, check=False,
                               diff=False)
        '''

        self.loader = DataLoader()

        self.passwords = dict(vault_pass='secret')

        self.inventory = InventoryManager(
            loader=self.loader, sources=self.resource
        )

        # 添加host的登录信息
        self.convert_hosts()
        # self.gen_inventory()
        self.variable_manager = VariableManager(
            loader=self.loader, inventory=self.inventory)
        # self.variable_manager.extra_vars

    def my_add_group(self, hosts, groupname, groupvars=None):
        """
        add hosts to a group
        """
        my_group = Group(name=groupname)
        # if group variables exists, add them to group
        if groupvars:
            for key, value in groupvars.items():
                my_group.set_variable(key, value)

                # add hosts to group
        for host in hosts:
            # set connection variables
            hostname = host.get("hostname")
            hostip = host.get('ip', hostname)
            hostport = host.get("port")
            username = host.get("username")
            password = host.get("password")
            ssh_key = host.get("ssh_key")
            my_host = Host(name=hostname, port=hostport)
            my_host.set_variable('ansible_ssh_host', hostip)
            my_host.set_variable('ansible_ssh_port', hostport)
            my_host.set_variable('ansible_ssh_user', username)
            my_host.set_variable('ansible_ssh_pass', password)
            my_host.set_variable('ansible_ssh_private_key_file', ssh_key)

            # set other variables
            for key, value in host.items():
                if key not in ["hostname", "port", "username", "password"]:
                    my_host.set_variable(key, value)
                    # add to group
            my_group.add_host(my_host)

        self.inventory.add_group(my_group)

    def gen_inventory(self):
        """
        add hosts to inventory.
        """
        if isinstance(self.resource_list, list):
            self.my_add_group(self.resource, 'default_group')
        elif isinstance(self.resource_list, dict):
            for groupname, hosts_and_vars in self.resource_list.items():
                self.my_add_group(hosts_and_vars.get("hosts"), groupname, hosts_and_vars.get("vars"))


    def convert_hosts(self):
        """
        @summary:这个位置并没有考虑 添加主机组的情况,需要修改
        :return:
        """
        for host in self.resource_list:
            if host['hostname'] in self.inventory.hosts:
                # set connection variables
                hostname = host.get("hostname")
                hostip = host.get('ip', hostname)
                hostport = host.get("port")
                username = host.get("username")
                password = host.get("password")
                ssh_key = host.get("ssh_key")
                my_host = Host(name=hostname, port=hostport)
                my_host.set_variable('ansible_ssh_host', hostip)
                my_host.set_variable('ansible_ssh_port', hostport)
                my_host.set_variable('ansible_ssh_user', username)
                my_host.set_variable('ansible_ssh_pass', password)
                my_host.set_variable('ansible_ssh_private_key_file', ssh_key)

                # set other variables
                for key, value in host.items():
                    if key not in ["hostname", "port", "username", "password"]:
                        my_host.set_variable(key, value)
                self.inventory.hosts[hostname] = my_host

    def run(self, host_list, module_name, module_args):
        """
        run module from andible ad-hoc.
        module_name: ansible module_name
        module_args: ansible module args
        """
        # create play with tasks
        play_source = dict(
            name="Ansible Play",
            hosts=host_list,
            gather_facts='no',
            tasks=[dict(action=dict(module=module_name, args=module_args))]
        )
        play = Play().load(play_source, variable_manager=self.variable_manager, loader=self.loader)

        # actually run it
        tqm = None
        self.callback = ResultsCollector()
        try:
            tqm = TaskQueueManager(
                inventory=self.inventory,
                variable_manager=self.variable_manager,
                loader=self.loader,
                options=self.options,
                passwords=self.passwords,
                stdout_callback='default',
            )
            tqm._stdout_callback = self.callback
            result = tqm.run(play)

        finally:
            if tqm is not None:
                tqm.cleanup()

    def run_playbook(self, host_list, filenames='/home/work/test.yml'):
        """
        run ansible palybook
        """
        try:
            self.callback = ResultsCollector()
            # playbook的路径
            '''
            filenames = [BASE_DIR + '/handlers/ansible/v1_0/sudoers.yml']
            logger.info('ymal file path:%s' % filenames)
            template_file = TEMPLATE_DIR  # 模板文件的路径
            if not os.path.exists(template_file):
                logger.error('%s 路径不存在 ' % template_file)
                sys.exit()
            '''

            extra_vars = {}  # 额外的参数 sudoers.yml以及模板中的参数，它对应ansible-playbook test.yml --extra-vars "host='aa' name='cc' "
            host_list_str = ','.join([item for item in host_list])
            '''
            extra_vars['host_list'] = host_list_str
            extra_vars['username'] = role_name
            extra_vars['template_dir'] = template_file
            extra_vars['command_list'] = temp_param.get('cmdList')
            extra_vars['role_uuid'] = 'role-%s' % role_uuid
            '''
            # self.variable_manager.extra_vars = {'customer': 'test', 'disabled': 'yes'}
            ##logger.info('playbook 额外参数:%s'%self.variable_manager.extra_vars)
            # actually run it
            executor = PlaybookExecutor(
                playbooks=filenames, inventory=self.inventory, variable_manager=self.variable_manager,
                loader=self.loader,
                options=self.options, passwords=self.passwords,
            )
            executor._tqm._stdout_callback = self.callback
            a = executor.run()

        except Exception as e:
            logger.error("run_playbook:%s"%e)
            pass

    def get_result(self):
        self.results_raw = {'success': {}, 'failed': {}, 'unreachable': {}}
        for host, result in self.callback.host_ok.items():
            self.results_raw['success'][host] = result._result

        for host, result in self.callback.host_failed.items():
            self.results_raw['failed'][host] = result._result

        for host, result in self.callback.host_unreachable.items():
            self.results_raw['unreachable'][host] = result._result['msg']

        return self.results_raw


class ResultsCollector(CallbackBase):

    def __init__(self, *args, **kwargs):
        super(ResultsCollector, self).__init__(*args, **kwargs)
        self.host_ok = {}
        self.host_unreachable = {}
        self.host_failed = {}

    def v2_runner_on_unreachable(self, result):
        self.host_unreachable[result._host.get_name()] = result

    def v2_runner_on_ok(self, result, *args, **kwargs):
        self.host_ok[result._host.get_name()] = result

    def v2_runner_on_failed(self, result, *args, **kwargs):
        self.host_failed[result._host.get_name()] = result




class AnsiInterface(AnsibleAPI):
    def __init__(self, resource, resource_list, *args, **kwargs):
        super(AnsiInterface, self).__init__(resource, resource_list, *args, **kwargs)

    @staticmethod
    def deal_result(info):
        host_ips = info.get('success').keys()
        info['success'] = host_ips
        info["success_info"] = info.get("success")
        error_ips = info.get('failed')
        error_msg = {}
        for key, value in error_ips.items():
            temp = {}
            temp[key] = value.get('msg')
            error_msg.update(temp)
        info['failed'] = error_msg
        return info

    def copy_file(self, host_list, src=None, dest=None):
        """
        copy file
        """
        module_args = "src=%s  dest=%s" % (src, dest)
        self.run(host_list, 'copy', module_args)
        result = self.get_result()
        return result

    def exec_command(self, host_list, module,cmds):
        """
        commands
        """
        self.run(host_list, module, cmds)
        result = self.get_result()
        return result

    def exec_script(self, host_list, path):
        """
        在远程主机执行shell命令或者.sh脚本
        """
        self.run(host_list, 'shell', path)
        result = self.get_result()
        return self.deal_result(result)

    def user(self, host_list, params):
        """
        在远程主机添加用户
        """
        module_args = ''
        for i in params:
            module_args += i + '=' + params[i] + ' '
        self.run(host_list, 'user', module_args)
        result = self.get_result()
        return self.deal_result(result)

    def authorized_key(self, host_list, params):
        """
        在远程主机添加用户
        """
        module_args = ''
        for i in params:
            if i == 'key':
                module_args += i + '="' + params[i] + '" '
            else:
                module_args += i + '=' + params[i] + ' '
        self.run(host_list, 'authorized_key', module_args)
        result = self.get_result()
        return self.deal_result(result)

    def exec_playbook(self, host_list, path):
        """
        在远程主机执行ansible playbook
        """
        self.run_playbook(host_list, path)

        result = self.get_result()
        return self.deal_result(result)

    def ping(self, host_list, args):
        """
        commands
        """
        self.run(host_list, 'ping', args)
        result = self.get_result()
        return self.deal_result(result)

    def uploadFile(self,resource,srcFilePath,srcFileList,destPath,destFileName=None):
        """
        @summary:复制源文件地址到目标地址上
        :param srcFilePath: 源文件目录
        :param scrFileList: 源文件列表
        :param destPath: 目标目录
        :param destFileName: 目标文件名称
        :return: 执行结果
        """
        logger.info('本地上传目录：{},远程接收目录：{}'.format(srcFilePath, destPath))
        otherErrorMessage = ''
        failFileList = []
        successTotal = 0
        if not os.path.exists(srcFilePath):
            logger.warning('本地目录不存在：{}'.format(srcFilePath))
            return False

        if not srcFileList:
            srcFileList=os.listdir(srcFilePath)
        total = len(srcFileList)
        localFilePath = srcFilePath + '/'
        remotePath = destPath + '/'
        for lfl in srcFileList:
            try:
                localFile=os.path.join(localFilePath,lfl)
                if destFileName!=None and total == 1:
                    remouteFile=os.path.join(remotePath,destFileName)
                else:
                    remouteFile=os.path.join(remotePath,lfl)
                if not os.path.exists(localFile):
                    errorMessage='本地文件不存在:%s' % localFile
                    failFileList.insert(0, (lfl,errorMessage))
                    continue
                logger.info('开始上传文件:{},远程目录：{}'.format(lfl,remouteFile))
                module_args = "src=%s  dest=%s" % (localFile, remouteFile)
                self.run(resource,module_name="copy",module_args=module_args)
                result = self.get_result()
                if result["success"]:
                    logger.info('文件:{}上传成功!'.format(localFile))
                    successTotal += 1
                else:
                    logger.warning("文件:{}上传失败!".format(localFile))
                    successTotal -= 1
            except Exception as e:
                logger.warning('上传文件发生异常：{}'.format(e))
                errorMessage= '上传文件发生异常:%s' % str(e)
                failFileList.insert(0, (lfl,errorMessage))
        if successTotal==total:
            logger.info('全部上传成功！')
            uploadFlag=0
        elif successTotal==0:
            logger.warning('全部上传失败！')
            uploadFlag=-1
        else:
            uploadFlag=-2
            logger.warning('部分上传成功！')
        return uploadFlag,otherErrorMessage,failFileList

if __name__ == "__main__":
    """
      参数格式1:
        resource和resource_list一一对应, 如果配置了免密钥登陆, 可以不传resource_list
        resource_list = [{"hostname":"192.168.175.3","port":"22","username":"root","password":"123456","ip":'192.168.175.3'}]
        resource = '192.168.175.3,' // 逗号不能少，即使只有一个
      参数格式2:
        resource = '/home/work/hosts'
    """
    resource_list = [
        {"hostname": "193.112.185.171", "port": "22", "username": "root", "password": "", "ip": '193.112.185.171',
         'ssh_key': '',"remote_path":"/home/mcbadm/"},

        # {
        #     "hostname":"172.20.10.14","port":"22","username":"wuwei","password":"tarena","ip":"172.20.10.14","ssh_key":""
        # },
        # {
        #     "hostname":"192.168.119.142","port":"22","username":"mcbadm","password":"","ip":"192.168.119.142","ssh_key":""
        # }
    ]
    resource_dict = {
        "test1": {
            "hosts": [
                {"hostname": "192.168.119.142", "port":22,"username": "mcbadm","password":"","ip":"192.168.119.142","ssh_key":""},
            ],
            "vars": {"var1": "", "var2": ""}
        },
        "test2": {
            "hosts": [
                {"hostname": "127.0.0.1","port":"22","username":"wuwei","password":"tarena","ip":"127.0.0.1","ssh_key":""}
            ],
            "vars": {"var1": "value1", "var2": "value2"}
        },
    }
    resource = '193.112.185.171,'
    # resource = '/home/work/hosts'
    interface = AnsiInterface(resource, resource_list)
    '''
    print "copy: ", interface.copy_file(['172.20.3.18', '172.20.3.31'], src='/Users/majing/test1.py', dest='/opt')
    print "commands: ", interface.exec_command(['172.20.3.18', '172.20.3.31'], 'hostname')
    print "shell: ", interface.exec_script(['172.20.3.18', '172.20.3.31'], 'chdir=/home ls')
    print "shell: ", interface.exec_script(['172.20.3.18', '172.20.3.31'], 'sh /opt/test.sh')
    '''
    # print "create user: ", interface.user(['172.20.3.18'], 'test')
    print("commands: ", interface.exec_command(host_list=resource,module="shell",cmds='ls'))
    # print(interface.exec_playbook(resource,["/home/wuwei/桌面/deploy_automation/automation/job/script/ansibleTask/test.yml"]))
