import subprocess
import os

while True:
    command = 'strace ./casync extract -v --without=privileged --store=./flag.castr ./flag.caidx flag/ 2> tmpfile; cat tmpfile | grep "No such file" | grep ".cacnk"'
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
    output = process.communicate()

    if not ("cacnk" in output[0]):
        break
    
    i1 = output[0].find("flag.castr")
    i2 = output[0].find("cacnk") + 5
    f = output[0][i1:i2]

    os.system('wget --user=admin --password=rainbow http://167.99.233.88/private/' + f)
    os.system('mkdir ' + f[:15])
    os.system('mv ' + f[16:] + ' ' + f[:15])
