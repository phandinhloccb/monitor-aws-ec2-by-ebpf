sudo useradd ebpfuser                 
sudo usermod -aG wheel ebpfuser    
sudo passwd ebpfuser   
su - ebpfuser                                         
curl google.com    
sudo bash -c 'echo hello'                                      
sudo userdel ebpfuser
sudo userdel -r ebpfuser