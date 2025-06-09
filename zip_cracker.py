import concurrent.futures
import time
import rarfile
import requests
import os
import psutil
import pyzipper

#function that returns the optimal maximum of processes the script can run
#based on user's hardware and current load on the CPU
def get_optimal_cpu() -> int:
    total_cpus : int = os.cpu_count() #total number of available CPU's in user's hardware
    current_cpu_load : float = psutil.cpu_percent(interval=1) #current % of load on the CPU's
    optimal_maximum_processes : int = 1 #saving here the maximum number of processes the PC can run concurrently
    if current_cpu_load > 80:
        #if the current load is more than 80%, use half
        optimal_maximum_processes = max(1, total_cpus // 2)
    elif current_cpu_load > 50:
        #if the current load is more than 50%, use 3/4 of the cores
        optimal_maximum_processes = max(1, (total_cpus * 3) // 4)
    else:
        #if the current load is less than 50%, use all cores
        optimal_maximum_processes = total_cpus
    return optimal_maximum_processes

#function that splits the password list based on the number of processes the PC can manage
#returns a list with lists as elements, element for each process
def split_passwords_list(max_processes) -> list[list[str]]:
    response = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt")
    passwords_list : list[str] = response.text.splitlines() #taking all the passwords from the raw page, shoving them into a list
    divided_passwords_list : list[list[str]] = [] #declaring the divided list to return
    for _ in range(max_processes):
        #appending sub-lists based on the number of processes
        divided_passwords_list.append([])

    chunk : int = 0 #iteratable for appending the passwords
        #iterate on the password list, and for every element, add it to the next "chunk" (chunk = sub-list = process)
    for i in passwords_list:
        if chunk == len(divided_passwords_list):
            chunk = 0
        divided_passwords_list[chunk].append(i)
        chunk += 1

    return divided_passwords_list


#function that returns the name of the zip file in a string format
#returns a string of the archive name
def get_name_for_extract(path) -> str:
    #methods for .zip files, using pyzipper module
    if path.endswith(".zip"):
        try:
            with pyzipper.AESZipFile(path, 'r') as f:
                return f.filename #returning the archive name
        except:
            print("error getting file name")
            return ""
    #methods for .rar files, using rarfile module
    else:
        try:
            with rarfile.RarFile(path, "r") as f:
                return f.filename #returning the archive name
        except:
            print("error getting file name")
            return ""

#function that gets the directory the archive exists in
#returns a string of the directory
def get_archive_directory(path):
    last_slash : int = path.rfind("/") #the index of the last slash, before the file name
    if last_slash == -1:
        last_slash = path.rfind("\\") #the index of the last slash, before the file name
    path_name : str = path[0:last_slash] #slicing the string from the start until the last folder in the path
    return path_name

#function that gets the name of the first file in the archive to test the password on.
#returns a string of the file name/directory of the file inside the archive
def get_filename_for_testing(path) -> str:
    #methods for .zip files, using pyzipper module
    if path.endswith(".zip"):
        with pyzipper.AESZipFile(path, "r") as f:
            for i in f.infolist(): #look at every element of the archive
                if not i.is_dir(): #if it's a file
                    return i.filename
    #methods for .rar files, using rarfile module
    else:
        with rarfile.RarFile(path, "r") as f:
            for i in f.infolist(): #look at every element of the archive
                if i.is_file(): #if it's a file
                    return i.filename
    return ""

#function that tries every password in the chunk it receives on the archive
#returns a correct password if not, else an empty string
def try_pass(chunk, path) -> str:
    name = get_filename_for_testing(path) #getting the file for testing
    print(name)
    #if the archive is not empty:
    if name:
        # methods for .zip files, using pyzipper module
        if path.endswith(".zip"):
            for password in chunk:
                with pyzipper.AESZipFile(path, "r") as f:
                    try:
                        f.read(name, pwd=bytes(password.encode())) #for the password given, try reading the file
                        return password
                    except:
                        #if the password is incorrect, continue to the next password
                        continue
        else:
            # methods for .rar files, using rarfile module
            for password in chunk:
                with rarfile.RarFile(path, "r") as f:
                    try:
                        f.read(name, pwd=password) #for the password given, try reading the file
                        return password
                    except:
                        # if the password is incorrect, continue to the next password
                        continue

    return ""

#functiong that creates different processes, to crack the code faster
#returns the correct password, else returns an empty string
def brute_cracking(path) -> str:
    optimal_max_processes : int = get_optimal_cpu() #getting the number of optimal maximum number of processes
    passwords_list_chunks : list[list[str]] = split_passwords_list(optimal_max_processes) #getting the divided password list relative to the number of processes
    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = [executor.submit(try_pass, passwords_list_chunks[i], path) for i in range(optimal_max_processes)]
        # ^    list of all processes, started and joined together by the ProcessPoolExecutor
        for f in concurrent.futures.as_completed(results):
            #look in every process and check the result
            if f.result() != "":
                #if a password was found (not an empty string)
                return f.result()
    return ""

#function that extracts all the data from the archive
def extract_zip(path, password, path_to_extract) -> None:
    # methods for .zip files, using pyzipper module
    if path.endswith(".zip"):
        with pyzipper.AESZipFile(path, "r") as f:
            f.extractall(path_to_extract, pwd=bytes(password.encode()))
    # methods for .rar files, using rarfile module
    else:
        with rarfile.RarFile(path, "r") as f:
            f.extractall(path_to_extract, pwd=password.encode)


if __name__ == '__main__':
    while True:
        path_to_zip : str = input("Enter the path of the zip or rar file: ") #asking the user for the path of the compressed file
        # looping until user gives a correct format and correct directory
        if path_to_zip.endswith(".zip") or path_to_zip.endswith(".rar"):
            if os.path.exists(path_to_zip):
                break
            else:
                print(f"Directory {path_to_zip} doesn't exist")
        else:
            print("incorrect file type: not a zip or rar file")

    start : float = time.perf_counter() #starting measuring the time until the brute_cracking() finishing
    print("Please wait, this can take some time...")
    correct_password : str = brute_cracking(path_to_zip) #actual brute force cracking
    finish : float = time.perf_counter() #finish measuring the time
    print(f"Finished in: {finish - start} seconds") #printing total time for the cracking
    if not correct_password:
        print("couldn't crack password or compressed file is empty without files")
    else:
        #option to extract archive starts here
        print(f"Password cracked: {correct_password}")
        choice = input("Would you like to extract the content of the compressed file? (Y/<any other key to exit>]): ")
        if choice.lower() == 'y': #user chose to extract data
            print("making folder...")
            extracted_content_path : str = os.path.join(get_archive_directory(path_to_zip), f"{get_name_for_extract(path_to_zip)}_extracted")  # path to extracted folder
            i = 1
            while True:
                try:
                    os.makedirs(extracted_content_path) #trying to create the folder
                    break
                except:
                    #a folder with the same name already existing, so making a new folder name
                    extracted_content_path = os.path.join(get_archive_directory(path_to_zip), f"{get_name_for_extract(path_to_zip)}_extracted_{i}")
                i += 1
            print("extracting data...")
            extract_zip(path_to_zip, correct_password, extracted_content_path) #extracting the data to the new folder
            print("done!!")



