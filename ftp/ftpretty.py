#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2020 anqi.huang@outlook.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
from ftplib import FTP, error_perm
import re

from dateutil import parser
from progressbar import *

try:
    from ftplib import FTP_TLS
except ImportError:
    FTP_TLS = None

if sys.version_info[0] < 3:
    PY2 = True
    PY3 = False
    from cStringIO import StringIO

    buffer_type = StringIO
    file_type = file
else:
    PY2 = False
    PY3 = True
    from io import IOBase, BytesIO

    file_type = IOBase
    buffer_type = BytesIO


class ftpretty(object):
    """ A wrapper for FTP connections """
    conn = None
    port = None
    tmp_output = None
    relative_paths = set(['.', '..'])

    pbar = None
    downloaded = 0

    def __init__(self, host, user, password,
                 secure=False, passive=True, ftp_conn=None, **kwargs):

        if 'port' in kwargs:
            self.port = kwargs['port']
            del kwargs['port']

        if ftp_conn:
            self.conn = ftp_conn
        elif secure and FTP_TLS:
            if self.port:
                FTP_TLS.port = self.port
            self.conn = FTP_TLS(host=host, user=user, passwd=password, **kwargs)
            self.conn.prot_p()
        else:
            if self.port:
                FTP.port = self.port
            self.conn = FTP(host=host, user=user, passwd=password, **kwargs)

        if not passive:
            self.conn.set_pasv(False)

    def __getattr__(self, name):
        """ Pass anything we don't know about, to underlying ftp connection """

        def wrapper(*args, **kwargs):
            method = getattr(self.conn, name)
            return method(*args, **kwargs)

        return wrapper

    def show_progress(self, download_size, total_size):
        if self.pbar is None:
            widgets = ['Downloading: ', Percentage(), ' ',
                       Bar(marker='#', left='[', right=']'),
                       ' ', ETA(), ' ', FileTransferSpeed()]

            self.pbar = ProgressBar(widgets=widgets, maxval=total_size)
            self.pbar.start()

        self.downloaded += download_size
        self.pbar.update(self.downloaded)
        if self.downloaded == total_size:
            self.pbar.finish()
            pbar = None
            downloaded = 0

    def handle_download(self, data, file, total_size):
        file.write(data)
        self.show_progress(len(data), total_size)

    def get(self, remote, local=None):
        """ Gets the file from FTP server
            local can be:
                a file: opened for writing, left open
                a string: path to output file
                None: contents are returned
        """
        if isinstance(local, file_type):  # open file, leave open
            local_file = local
        elif local is None:  # return string
            local_file = buffer_type()
        else:  # path to file, open, write/close return None
            local_file = open(local, 'wb')

        total_size = self.conn.size(remote)
        # self.conn.retrbinary("RETR %s" % remote, local_file.write)
        self.conn.retrbinary("RETR %s" % remote, lambda data: self.handle_download(data, local_file, total_size))

        if isinstance(local, file_type):
            pass
        elif local is None:
            contents = local_file.getvalue()
            local_file.close()
            return contents
        else:
            local_file.close()

        return None

    def put(self, local, remote, contents=None, quiet=False):
        """ Puts a local file (or contents) on to the FTP server
            local can be:
                a string: path to inpit file
                a file: opened for reading
                None: contents are pushed
        """
        remote_dir = os.path.dirname(remote)
        remote_file = os.path.basename(local) \
            if remote.endswith('/') else os.path.basename(remote)

        if contents:
            # local is ignored if contents is set
            local_file = buffer_type(contents)
        elif isinstance(local, file_type):
            local_file = local
        else:
            local_file = open(local, 'rb')
        current = self.conn.pwd()
        self.descend(remote_dir, force=True)

        size = 0
        try:
            self.conn.storbinary('STOR %s' % remote_file, local_file)
            size = self.conn.size(remote_file)
        except:
            if not quiet:
                raise
        finally:
            local_file.close()
            self.conn.cwd(current)
        return size

    def upload_tree(self, src, dst, ignore=None):
        """Recursively upload a directory tree.
        Although similar to shutil.copytree we don't follow symlinks.
        """
        names = os.listdir(src)
        if ignore is not None:
            ignored_names = ignore(src, names)
        else:
            ignored_names = set()

        try:
            dst = dst.replace('\\', '/')
            self.conn.mkd(dst)
        except error_perm:
            pass

        errors = []
        for name in names:
            if name in ignored_names:
                continue
            src_name = os.path.join(src, name)
            dst_name = os.path.join(dst, name)
            try:
                if os.path.islink(src_name):
                    pass
                elif os.path.isdir(src_name):
                    self.upload_tree(src_name, dst_name, ignore)
                else:
                    # Will raise a SpecialFileError for unsupported file types
                    self.put(src_name, dst_name)
            except Exception as why:
                errors.append((src_name, dst_name, str(why)))

        return dst

    def list(self, remote='.', extra=False, remove_relative_paths=False):
        """ Return directory list """
        if extra:
            self.tmp_output = []
            self.conn.dir(remote, self._collector)
            directory_list = split_file_info(self.tmp_output)
        else:
            directory_list = self.conn.nlst(remote)

        if remove_relative_paths:
            return list(filter(self.is_not_relative_path, directory_list))

        return directory_list

    def is_not_relative_path(self, path):
        if isinstance(path, dict):
            return path.get('name') not in self.relative_paths
        else:
            return path not in self.relative_paths

    def descend(self, remote, force=False):
        """ Descend, possibly creating directories as needed """
        remote_dirs = remote.split('/')
        for directory in remote_dirs:
            try:
                self.conn.cwd(directory)
            except Exception:
                if force:
                    self.conn.mkd(directory)
                    self.conn.cwd(directory)
        return self.conn.pwd()

    def delete(self, remote):
        """ Delete a file from server """
        try:
            self.conn.delete(remote)
        except Exception:
            return False
        else:
            return True

    def cd(self, remote):
        """ Change working directory on server """
        try:
            self.conn.cwd(remote)
        except Exception:
            return False
        else:
            return self.pwd()

    def pwd(self):
        """ Return the current working directory """
        return self.conn.pwd()

    def rename(self, remote_from, remote_to):
        """ Rename a file on the server """
        return self.conn.rename(remote_from, remote_to)

    def close(self):
        """ End the session """
        try:
            self.conn.quit()
        except Exception:
            self.conn.close()

    def _collector(self, line):
        """ Helper for collecting output from dir() """
        self.tmp_output.append(line)


def split_file_info(fileinfo):
    """ Parse sane directory output usually ls -l
        Adapted from https://gist.github.com/tobiasoberrauch/2942716
    """
    current_year = datetime.datetime.now().strftime('%Y')
    files = []
    for line in fileinfo:
        parts = re.split(
            r'^([\-dbclps])' +  # Directory flag [1]
            r'((?:[r-][w-][-xsStT]){3})\s+' +  # Permissions [2]
            r'(\d+)\s+' +  # Number of items [3]
            r'([a-zA-Z0-9_-]+)\s+' +  # File owner [4]
            r'([a-zA-Z0-9_-]+)\s+' +  # File group [5]
            r'(\d+)\s+' +  # File size in bytes [6]
            r'(\w{3}\s+\d{1,2})\s+' +  # 3-char month and 1/2-char day of the month [7]
            r'(\d{1,2}:\d{1,2}|\d{4})\s+' +  # Time or year (need to check conditions) [+= 7]
            r'(.+)$',  # File/directory name [8]
            line
        )

        date = parts[7]
        time = parts[8] if ':' in parts[8] else '00:00'
        year = parts[8] if ':' not in parts[8] else current_year
        dt_obj = parser.parse("%s %s %s" % (date, year, time))

        files.append({
            'directory': parts[1],
            'perms': parts[2],
            'items': parts[3],
            'owner': parts[4],
            'group': parts[5],
            'size': int(parts[6]),
            'date': date,
            'time': time,
            'year': year,
            'name': parts[9],
            'datetime': dt_obj
        })
    return files
