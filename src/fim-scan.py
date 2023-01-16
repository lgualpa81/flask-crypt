import hashlib
import os
import datetime
import socket
import google.cloud.logging
#import logging

hostname=socket.gethostname()

client = google.cloud.logging.Client()
logger = client.logger('python_fim_scan')

original_md5 = ''

debugProcess = 0
scanLog="fim-scan.log"
scanDirectory="/"
scanFilesResult="scannedFiles.txt"
lockFile="fim-scan.lock"

ignoreDir = []
ignoreDir.append("/root")
ignoreDir.append("venv/test\windows")

ignoreDir.append("/var/log")
ignoreDir.append("/log/journal")
ignoreDir.append("/root")
ignoreDir.append("/usr/share")
ignoreDir.append("/logs")
ignoreDir.append("/bin")
ignoreDir.append("/boot")
ignoreDir.append("/lib")
ignoreDir.append("/lib64")
ignoreDir.append("/media")
ignoreDir.append("/mnt")
ignoreDir.append("/dev")
ignoreDir.append("/proc")
ignoreDir.append("/srv")
ignoreDir.append("/sys")
ignoreDir.append("/usr")
ignoreDir.append("/tmp")
ignoreDir.append("/run")
ignoreDir.append("/home")
ignoreDir.append("/etc/alternatives")
ignoreDir.append("/var/lib")
ignoreDir.append("/opt/auth/.git")
ignoreDir.append("/monitor")


listFiles = []
listScannedFiles=[]
listScannedFilesBase=[]

reportNew=[]
reportFailed=[]
reportDeleted=[]

newScan = []

def checksumfile(file_name, original_md5):
    response=""
    if  os.path.exists(file_name):
        md5_returned = hashlib.md5(open(file_name, 'rb').read()).hexdigest()
    else:
        md5_returned="00000000000000000000000000000000 "
        response = "FAILED|" + md5_returned

    if original_md5=="NEW":
        response = "NEW FILE|" + md5_returned
    else:
        if original_md5 == md5_returned:
            response="OK|"+md5_returned
        else:
            response="FAILED|"+md5_returned
    return response


def getFiles(folder,directorios_ignorados):
    listFilesTmp=[]
    for directoryName, dirs, ficheros in os.walk(folder):
        if not directoryName in directorios_ignorados:
        #    print("DISABLED", directoryName)
        #else:
            if  getFolderEnable(directorios_ignorados,directoryName) ==0 :
                for nombre_fichero in ficheros:
                    listFilesTmp.append(directoryName + "/" + nombre_fichero)
                    #print("ENABLE  ", directoryName)
            #else:
            #    print("DISABLED", directoryName)
    return listFilesTmp

def getFolderEnable(directorios_ignorados,directoryName):
    resp=0
    for item in directorios_ignorados:
        tmplen = len(item)
        if item == directoryName[0:tmplen]:
            resp=1
            break
    return resp



def getCheckSumScanned(newFile,listScannedFilesBase):
    for item in listScannedFilesBase:
        tmpArray = item.split("|")
        tmpFile = tmpArray[2]
        tmpChecksum=tmpArray[1]
        if newFile==tmpFile:
            tmpScanned = tmpChecksum
            break
    return tmpScanned

if __name__ == '__main__':

    if os.path.exists(lockFile):
        print(datetime.datetime.now().strftime("%c"),'A scan is already in progess.')
        logger.log_struct({'process':'FIM','host': hostname, 'status': 'A scan is already in progess.' })
        exit(666)
    else:
        with open(lockFile, 'w') as outfile:
            outfile.write("{}\n".format(datetime.datetime.now().strftime("%c")+" Start"))

    # Carga de archivos para el analisis
    print(datetime.datetime.now().strftime("%c"),'Gathering file manifest')
    logger.log_struct({'process':'FIM','host': hostname, 'status': 'Gathering file manifest'})

    listFiles = getFiles(scanDirectory, ignoreDir)
    if debugProcess ==1 :
        for itm in listFiles:
           print(itm)

    #Cargar el resultado del analisis anterior
    if os.path.exists(scanFilesResult):
        with open(scanFilesResult, 'r') as f:
            listScannedFilesBase = f.readlines()

    #eliminar salto de linea
    contador=0
    for itemScanned in listScannedFilesBase:
        itemScannedLen = len(itemScanned)
        itemScannedNew = itemScanned[:itemScannedLen - 1]
        listScannedFilesBase[contador]=itemScannedNew
        contador = contador + 1

    #print(listScannedFilesBase)

    # print(".................................................")

    # cargar en arreglo los archivos analizados
    for scannedFile in listScannedFilesBase:
        resp=scannedFile.split("|")
        listScannedFiles.append(resp[2])

    # print("Archivos analizados .... ")
    # print(listScannedFiles)

    # Analisis de archivos nuevos y existentes en el analisis anterior
    print(datetime.datetime.now().strftime("%c"),'Starting fingerprint comparison')
    logger.log_struct({'process':'FIM','host': hostname, 'status': 'Starting fingerprint comparison'})
    for newFile in listFiles:

        if newFile in listScannedFiles:
            original_md5=getCheckSumScanned(newFile, listScannedFilesBase)
            dataCheckSum = checksumfile(newFile, original_md5) + "|" + newFile

            split_response = dataCheckSum.split("|")
            if not split_response[0] == "OK":
                reportFailed.append(split_response[1] + " " + split_response[2] + " " + split_response[0])
        else:
            dataCheckSum = checksumfile(newFile, "NEW") + "|" + newFile

            split_response = dataCheckSum.split("|")
            if not split_response[0] == "OK":
                reportNew.append(split_response[1] + " " + split_response[2] + " " + split_response[0])

        newScan.append(dataCheckSum)


    print(datetime.datetime.now().strftime("%c"),'Comparison scan complete')
    logger.log_struct({'process':'FIM','host': hostname, 'status': 'Comparison scan complete'})

    # Validacion de los archivos eliminados
    for archivo_viejo in listScannedFiles:
        if not archivo_viejo in listFiles:
            reportDeleted.append("................................ "+archivo_viejo+" DELETED")

    # Mostrar el resultado del analisis
    if len(reportNew) > 0:
        print(datetime.datetime.now().strftime("%c"),'New files found')
        logger.log_struct({'process':'FIM','host': hostname, 'status': 'New files found'})
        for rep in reportNew:
            print("\t",rep)
            #logger.setLevel(logging.WARN)
            logger.log_struct({'process':'FIM','host': hostname, 'status': 'NEW', 'Detail_report': rep})

    if len(reportFailed) > 0:
        print(datetime.datetime.now().strftime("%c"),'Updating fingerprint on failed files')
        logger.log_struct({'process':'FIM','host': hostname, 'status': 'Updating fingerprint on failed files'})
        for rep in reportFailed:
            print("\t",rep)
            #logger.setLevel(logging.WARN)
            logger.log_struct({'process':'FIM','host': hostname, 'status': 'FAILED', 'Detail_report': rep})

    if len(reportDeleted) > 0:
        print(datetime.datetime.now().strftime("%c"),'Removing missing files from manifest')
        logger.log_struct({'process':'FIM','host': hostname, 'status': 'Removing missing files from manifest'})
        for rep in reportDeleted:
            print("\t",rep)
            #logger.setLevel(logging.WARN)
            logger.log_struct({'process':'FIM','host': hostname, 'status': 'DELETE', 'Detail_report': rep })

    # Guardar resultado del analisis
    with open(scanFilesResult, 'w') as outfile:
        for item in newScan:
            outfile.write("{}\n".format(item))
    if  os.path.exists(lockFile):
        os.remove(lockFile)

    print(datetime.datetime.now().strftime("%c"),'Scan complete')
    logger.log_struct({'process':'FIM','host': hostname, 'status': 'Scan complete'})


