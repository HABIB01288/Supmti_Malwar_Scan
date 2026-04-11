from __future__ import division
import sys
import os
import fnmatch
import re
import stat
import json
import mimetypes
import subprocess
import string
import time
import hashlib
import math
import threading
# Version actuelle du moteur de scan
VERSION = "0.3"
# Listes globales contenant les signatures de malwares
JAVASCRIPT_SIGNATURES = []# Signatures pour fichiers JavaScript
PHP_SIGNATURES = []# Signatures pour fichiers PHP
HASH_SIGNATURES = []# Signatures basées sur les hash MD5
HASHTABLE = {}
#Calcule le hash MD5 d'un fichier.
#  Utilisé pour comparer les fichiers aux signatures connues.
    
def checksum(fname):
    h = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# Détermine si un fichier est de type texte ou binaire.
# Les fichiers binaires ne sont pas analysés par expressions régulières.    
def isText(filename):
    try:
        with open(filename, "rb") as fh:
            sample = fh.read(512)
    except Exception:
        # If cannot read file as binary, treat as non-text
        return False

    if not sample:
        return True

    if b"\x00" in sample:
        return False

 # Vérification du taux de caractères imprimables    text_chars = bytes(range(32, 127)) + b"\n\r\t\b"
    non_text = sum(1 for c in sample if c not in text_chars)
    if (len(sample) == 0):
        return True
    if (float(non_text) / float(len(sample))) > 0.30:
        return False
    return True

class bcolors:
    # Codes ANSI pour afficher des messages colorés dans le terminal.
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def pmsg(msg, code = 'info'):
    #Affiche un message formaté avec un niveau d'information :
    #info, warning ou error.
    colorcode = bcolors.OKGREEN
    if code == 'warning':
        colorcode = bcolors.WARNING
    if code == 'error':
        colorcode = bcolors.FAIL
    print(f"{bcolors.OKBLUE}{bcolors.UNDERLINE}>>{bcolors.ENDC} {colorcode}{msg}{bcolors.ENDC}")

def progressBar(current, total, msg):
    # Affiche une barre de progression en pourcentage
    # pendant le scan ou le chargement des signatures.
    try:
        i = int((current / float(total)) * 100)
    except Exception:
        i = 0
    if i > 100:
        i = 100
    if i < 0:
        i = 0

    sys.stdout.write("\r" + f"{bcolors.OKBLUE}{bcolors.UNDERLINE}>>{bcolors.ENDC} {bcolors.OKGREEN}{msg} ({i}%)")
    sys.stdout.flush()

    if i == 100:
        sys.stdout.write("\n")
        sys.stdout.flush()

def FileScan(WebPath):
#Analyse récursive d'un dossier web afin de détecter :
#   - fichiers infectés (signatures ou hash)
#   - permissions non sécurisées
    totalInfected = 0
    totalInsecure = 0
    totalFiles = 0
    totalScanned = 0

    infectedFiles = []

    for root, dirnames, filenames in os.walk(WebPath):
        for filename in filenames:
            totalFiles += 1

    pmsg("Target: " + WebPath + " ("+str(totalFiles)+" files)")

    for root, dirnames, filenames in os.walk(WebPath):
        for filename in filenames:
            totalScanned += 1
            progressBar(totalScanned, totalFiles if totalFiles>0 else 1, "Scanning... please wait...")

            infected = False

            currentfile = os.path.join(root, filename)
            try:
                currentchecksum = checksum(currentfile)
            except Exception:
                continue

            if currentchecksum in HASHTABLE:
                infected = True

            if infected:
                details = {'filename': currentfile, 'malware': str(HASHTABLE[currentchecksum])}
                infectedFiles.append(details)
                totalInfected += 1
                continue

            if isText(currentfile) and not infected:
                try:
                    with open(currentfile, 'r', encoding='utf-8', errors='ignore') as fileHandle:
                        fileData = fileHandle.read()
                except Exception:
                    continue

                malware = ''
                found = False
                for signatureDefinition in JAVASCRIPT_SIGNATURES:
                    for signature in signatureDefinition.get("Database_Signatures", []):
                        for signatureExpression in signature.get("Malware_Signatures", []):
                            try:
                                regexp = re.compile(signatureExpression, re.IGNORECASE)
                                if regexp.search(fileData):
                                    infected = True
                                    malware = signature.get("Malware_Name", "Unknown")
                                    found = True
                                    break
                            except re.error:
                                pmsg("ERROR in signature regular expression. Aborting.", "error")
                                found = True
                                infected = False
                                break
                        if found:
                            break
                    if found:
                        break

                if infected:
                    details = {'filename': currentfile, 'malware': malware}
                    infectedFiles.append(details)
                    totalInfected += 1
                    continue

                THREADS = {}

                class ScanFileThread(threading.Thread):
                    def __init__(self, fileData, signatures):
                        threading.Thread.__init__(self)
                        self.infected = False
                        self.stopped = False
                        self.fileData = fileData
                        self.signatures = signatures
                        self.malware = ''

                    def run(self):
                        for signature in self.signatures:
                            if self.stopped:
                                break
                            for signatureExpression in signature.get("Malware_Signatures", []):
                                if self.stopped:
                                    break
                                try:
                                    regexp = re.compile(signatureExpression, re.IGNORECASE)
                                    if regexp.search(self.fileData):
                                        self.infected = True
                                        self.malware = signature.get("Malware_Name", "Unknown")
                                        break
                                except re.error:
                                    self.stopped = True
                                    break
                            if self.infected or self.stopped:
                                break

                    def isInfected(self):
                        return self.infected

                    def getMalwareName(self):
                        return self.malware

                    def stop(self):
                        self.stopped = True

                for signatureDefinition in PHP_SIGNATURES:
                    name = signatureDefinition.get("Database_Name", f"db_{len(THREADS)}")
                    THREADS[name] = ScanFileThread(fileData, signatureDefinition.get("Database_Signatures", []))
                    THREADS[name].start()

                while True:
                    alldone = True
                    for threadName in list(THREADS.keys()):
                        t = THREADS[threadName]
                        if t.is_alive():
                            alldone = False
                        else:
                            if t.isInfected():
                                infected = True
                                details = {'filename': currentfile, 'malware': t.getMalwareName()}
                                infectedFiles.append(details)
                                for tn in THREADS:
                                    THREADS[tn].stop()
                                alldone = True
                                break
                    if alldone:
                        break

                    time.sleep(0.01)

                if infected:
                    totalInfected += 1

    progressBar(1, 1, "Scanning... please wait...")
    for details in infectedFiles:
        pmsg("Infected file ("+details["malware"]+") found: "+details["filename"], "warning")

   
    pmsg("Scanning for insecure permissions...")
    if os.name == 'nt':
        pmsg("Permission check skipped on Windows (NTFS ACLs are not checked).", "info")
    else:
        folders = [x[0] for x in os.walk(WebPath)]
        for folder in folders:
            if os.path.isdir(folder):
                try:
                    mode = stat.S_IMODE(os.stat(folder).st_mode)
            
                    insecure = False
                    if mode & stat.S_IWOTH:
                        insecure = True
                    if mode & stat.S_IWGRP:
                        insecure = True
                    if insecure:
                        pmsg(f"Insecure permission ({oct(mode)}) found on: {folder}", "warning")
                        totalInsecure += 1
                except Exception:
                    continue

    colorcode = "info"
    if totalInfected > 0 or totalInsecure > 0:
        colorcode = "error"
    pmsg("Scan completed. Found "+str(totalInfected)+" infected file(s). Found "+str(totalInsecure)+" insecure permission(s).", colorcode)

def LoadSignatures(SignaturesPath):
   
    totalDatabases = 0
    loadedDatabases = 0
    for root, dirnames, filenames in os.walk(SignaturesPath):
        for filename in filenames:
            totalDatabases += 1

    for root, dirnames, filenames in os.walk(os.path.join(SignaturesPath, "php")):
        for filename in fnmatch.filter(filenames, '*.json'):
            try:
                with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as fh:
                    signature = json.load(fh)
                PHP_SIGNATURES.append(signature)
                loadedDatabases += 1
                progressBar(loadedDatabases, totalDatabases if totalDatabases>0 else 1, "Loading signature database...")
            except IOError:
                pmsg("Unable to load signature file: " + filename, "error")

    # Load signatures for Javascript files
    for root, dirnames, filenames in os.walk(os.path.join(SignaturesPath, "js")):
        for filename in fnmatch.filter(filenames, '*.json'):
            try:
                with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as fh:
                    signature = json.load(fh)
                JAVASCRIPT_SIGNATURES.append(signature)
                loadedDatabases += 1
                progressBar(loadedDatabases, totalDatabases if totalDatabases>0 else 1, "Loading signature database...")
            except IOError:
                pmsg("Unable to load signature file: " + filename, "error")

    # Load signatures for MD5 hashes
    for root, dirnames, filenames in os.walk(os.path.join(SignaturesPath, "checksum")):
        for filename in fnmatch.filter(filenames, '*.json'):
            try:
                with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as fh:
                    signatures = json.load(fh)
                HASH_SIGNATURES.append(signatures)
                loadedDatabases += 1
                progressBar(loadedDatabases, totalDatabases if totalDatabases>0 else 1, "Loading signature database...")
            except IOError:
                pmsg("Unable to load signature file: " + filename, "error")

    pmsg("Building hashtable...")
    for signature in HASH_SIGNATURES:
        for signatureHash in signature.get("Database_Hash", []):
            HASHTABLE[signatureHash.get("Malware_Hash")] = signatureHash.get("Malware_Name")
    pmsg("Loaded "+str(len(HASHTABLE))+" malware hash signatures.")

if len(sys.argv) == 2:
    pmsg("Web Malware Scanner v"+VERSION)

    SignaturesPath = "./signatures/"
    if os.path.isdir(SignaturesPath):
        LoadSignatures(SignaturesPath)
    else:
        pmsg("Unable to find signatures database folder ("+SignaturesPath+"). Please check path.", "error")
        sys.exit()

    WebPath = sys.argv[1]
    if os.path.isdir(WebPath):
        FileScan(WebPath)
    else:
        pmsg("Unable to find web installation folder ("+WebPath+"). Please check path.", "error")
else:
    pmsg("Usage: python wms.py /path/to/web/installations")
