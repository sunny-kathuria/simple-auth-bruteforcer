import requests
from requests.exceptions import HTTPError
from requests.auth import HTTPBasicAuth
  


crendentials_found=[]
unauthenticated_server=[]
authenticated_server=[]


def opening_reading_file(file):
    file_data=open(file,'r')
    return file_data.readlines()


def forming_url(ip,port):
    url='http://'+ip+':'+port
    return url

def access_checker_and_cred_finder(ip_list,port_list,username_list,password_list):
    req_count=0
    for ip in ip_list:
        final_ip=ip.strip()
        for port in port_list:
            final_port=port.strip()
            headers={'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Mobile Safari/537.36'}
            try:
                url=forming_url(final_ip,final_port)
                print("Checking "+url)
                #request to check unauthenticated access, sending request without credentials
                req_count+=1
                r = requests.get(url, headers=headers)
                if(r.status_code==200):
                    unauthenticated_server.append(url)
                    print(url+ "doesn't need credentials, Unauthenticated Access")
                elif(r.status_code==401):

                    print(url+" needs credentials, Authentication required")
                    authenticated_server.append(url)
                    for username in username_list:
                        final_username=username.strip()
                        for password in password_list:
                            final_password=password.strip()
                            url=forming_url(final_ip,final_port)
                            credentials=final_username+":"+final_password
                            print(f'Trying credentials as {credentials}')
                            req_count+=1
                            #request to check credentials provided in username.txt and password.txt
                            r2 = requests.get(url, headers=headers, auth=HTTPBasicAuth(final_username,final_password))
                            
                            if(r2.status_code==200):
                                print('Success!, we found credentials')
                                crendentials_found.append(f'{credentials} for {url}')
                            else:
                                print("Incorrect")
                else:
                    print("Error Response Code "+str(r.status_code))   
            except HTTPError as http_err:
                print(f'HTTP error occurred: {http_err}') 
            except Exception as err:
                print(f'Other error occurred: {err}')
    return(req_count)

def result(req_count):
    if(len(crendentials_found)>0):
        print("\nFollowing credentials found ")
        print(*crendentials_found, sep = "\n")
    else:
        print("\nNo credentials found")
    if(len(unauthenticated_server)>0):
        print("\nUnauthenticated Server:")
        print(*unauthenticated_server,sep="\n")
    if(len(authenticated_server)>0):
        print("\nAuthenticated Server:")
        print(*authenticated_server,sep="\n")
    return print("\nTotal number of requests sent:"+str(req_count))




if __name__ == '__main__':
    #IPs.txt, ports.txt,username.txt,password.txt files should be present in same directory
    ip_list=opening_reading_file('IPs.txt')
    port_list=opening_reading_file('ports.txt')
    username_list=opening_reading_file('username.txt')
    password_list=opening_reading_file('password.txt')
    req_count=access_checker_and_cred_finder(ip_list,port_list,username_list,password_list)
    result(req_count)   
