# disables ptrace check until host reboot
sudo sysctl -w kernel.yama.ptrace_scope=0

# roll back
# sudo sysctl -w kernel.yama.ptrace_scope=1