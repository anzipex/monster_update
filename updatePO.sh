#!/bin/bash
#script written by anzipex

# exit codes:
#  0 - all is okay
# 74 - failed to mount
# 75 - not all blocks online

declare -a list_blocks=();
declare -a list_names=();
declare -a list_configurations=();
declare -a list_usb_pkgs=();
declare -a list_usb_pkgs_ver=();

# all packages:
declare -a MFI_PKGS=();
declare -a PNS_PKGS=();

USB_VOLUME="/media/usb"
UPDATE_DIR="wiseflyUpdate"
CONFIG_FILE="configuration.txt"
PKGS_LIST_FILE="packages.txt"
RESULT_FILE="result.txt"
USER="root"
PASSWORD="111"
NOKEY="-o StrictHostKeyChecking=no"

NO_BACKUPS_EXIST=$((0))
NUM_BLOCK=$((0))
NUM_NAME=$((-1))
NUM_CONFIGURATION=$((-1))
TYPE_BLOCK=$((0))
NUM_INDEX_ERROR=$((0))

check_usb_volume_mounted() {
    if mount | grep "on $USB_VOLUME type" > /dev/null
    then
        echo "$USB_VOLUME is mounted"
    else
        echo "Error. $USB_VOLUME is not mounted"
        exit 74
    fi
}

recreate_result_file() {
    if [ -f $USB_VOLUME/$UPDATE_DIR/logs/$RESULT_FILE ];
    then
        rm $USB_VOLUME/$UPDATE_DIR/logs/$RESULT_FILE && touch $USB_VOLUME/$UPDATE_DIR/logs/$RESULT_FILE
    else
        mkdir -p $USB_VOLUME/$UPDATE_DIR/logs && touch $USB_VOLUME/$UPDATE_DIR/logs/$RESULT_FILE
    fi
}

status_result_file() {
    echo "$@" >> $USB_VOLUME/$UPDATE_DIR/logs/$RESULT_FILE
}

check_file_packages_exist() {
    if [[ -f "$USB_VOLUME/$UPDATE_DIR/$PKGS_LIST_FILE" ]];
    then
        echo "$PKGS_LIST_FILE file exist"
    else
        echo "Error. $PKGS_LIST_FILE with packages not exist"
        status_result_file "FAIL. $PKGS_LIST_FILE with packages not exist"
        exit 1
    fi
}

check_file_packages_not_empty() {
    result=($(grep '[^[:space:]]' < "$USB_VOLUME/$UPDATE_DIR/$PKGS_LIST_FILE"))
    if [ -z "$result" ];
    then
        echo "Error. $PKGS_LIST_FILE is empty"
        status_result_file "FAIL. $PKGS_LIST_FILE is empty"
        exit 1
    fi
}

check_config_file_exist() {
    if [ -f "$USB_VOLUME/$UPDATE_DIR/$CONFIG_FILE" ];
    then
        echo "$CONFIG_FILE file exist"
    else
        echo "Error. $CONFIG_FILE file not exist"
        status_result_file "FAIL. $CONFIG_FILE file not exist"
        exit 1
    fi
}

check_config_file_not_empty() {
    result=($(grep '[^[:space:]]' < "$USB_VOLUME/$UPDATE_DIR/$CONFIG_FILE"))
    if [ -z "$result" ];
    then
        echo "Error. $CONFIG_FILE is empty"
        status_result_file "FAIL. $CONFIG_FILE is empty"
        exit 1
    fi
}

create_configuration_lists() {
    mapfile -t list_blocks <  <(awk -F, '{print $1}' "$USB_VOLUME/$UPDATE_DIR/$CONFIG_FILE")
    mapfile -t list_names <  <(awk -F, '{print $2}' "$USB_VOLUME/$UPDATE_DIR/$CONFIG_FILE")
    mapfile -t list_configurations <  <(awk -F, '{print $3}' "$USB_VOLUME/$UPDATE_DIR/$CONFIG_FILE")
}

check_type_exist() {
    for i in "${!list_names[@]}"
    do
        if [[ "${list_names[$i]:0:3}" == "MFI" || "${list_names[$i]:0:3}" == "PNS" ]];
        then
            exist=($(cat "$USB_VOLUME/$UPDATE_DIR/$PKGS_LIST_FILE" | grep "${list_names[$i]:0:3}" | awk '{print $2}'))
            if [[ -z "$exist" ]];
            then
                echo "Error. ${list_names[$i]:0:3} not found in $PKGS_LIST_FILE"
                status_result_file "FAIL. ${list_names[$i]:0:3} not found in $PKGS_LIST_FILE"
                exit 1
            fi
        else
            echo "Error. ${list_names[$i]:0:3} is not allowed"
            status_result_file "FAIL. ${list_names[$i]:0:3} is not allowed"
            exit 1
        fi
    done
}

create_packages_lists() {
    mapfile -t MFI_PKGS <  <(cat "$USB_VOLUME/$UPDATE_DIR/$PKGS_LIST_FILE" | grep "MFI" | awk '{print $2}')
    mapfile -t PNS_PKGS <  <(cat "$USB_VOLUME/$UPDATE_DIR/$PKGS_LIST_FILE" | grep "PNS" | awk '{print $2}')
}

check_conformity_mfi() {
    if [[ -n "${MFI_PKGS[@]}" ]];
    then
        for pkg in "${MFI_PKGS[@]}"
        do
            if [ ! -f $USB_VOLUME/$UPDATE_DIR/debs/MFI/$pkg*.deb ];
            then
                echo "Error. $pkg not found in $USB_VOLUME/$UPDATE_DIR/debs/MFI"
                status_result_file "FAIL. $pkg not found in $USB_VOLUME/$UPDATE_DIR/debs/MFI"
                exit 1
            fi
        done
    fi
}

check_conformity_pns() {
    if [[ -n "${PNS_PKGS[@]}" ]];
    then
        for pkg in "${PNS_PKGS[@]}"
        do
            if [ ! -f $USB_VOLUME/$UPDATE_DIR/debs/PNS/$pkg*.deb ];
            then
                echo "Error. $pkg not found in $USB_VOLUME/$UPDATE_DIR/debs/PNS"
                status_result_file "FAIL. $pkg not found in $USB_VOLUME/$UPDATE_DIR/debs/PNS"
                exit 1
            fi
        done
    fi
}

check_file_packages_conformity() {
    check_conformity_mfi
    check_conformity_pns
}

count_num_blocks() {
    num_blocks=${#list_blocks[@]}
}

determine_blocks_online() {
    for block in "${ips[@]}"
    do
        echo "$block is online"
    done
}

identify_blocks() {
    read -rd '' -a ips < <(nmap "${list_blocks[@]}" -n -sP | awk '/report/{printf("%s ", $NF)}');
    
    if [ "${#ips[@]}" -ne "$num_blocks" ];
    then
        echo "Error. ${#ips[@]} of $num_blocks blocks is online. $CONFIG_FILE has $num_blocks blocks"
        status_result_file "FAIL. ${#ips[@]} of $num_blocks blocks is online. $CONFIG_FILE has $num_blocks blocks"
        exit 75
    fi

    determine_blocks_online
}

check_deb_file_exist() {
    if [ -z "$result" ]
    then
        echo "WARNING! Backup ${list_pkgs_installed[$i]}_${list_versions_installed[$i]}_all.deb not found in cache"
        echo "Backup will not be restored if there are errors in install"
        NO_BACKUPS_EXIST="1"
    fi
}

check_checksum() {
    if [[ "$NO_BACKUPS_EXIST" == "0" ]];
    then
        installed_checksum=($(sshpass -p $PASSWORD ssh $NOKEY $USER@$ip cat /var/lib/dpkg/info/${list_pkgs_installed[$i]}.md5sums))
        deb_checksum=($(sshpass -p $PASSWORD ssh $NOKEY $USER@$ip dpkg -I /var/cache/apt/archives/${list_pkgs_installed[$i]}_${list_versions_installed[$i]}_all.deb md5sums))
        if [[ "${installed_checksum[@]}" != "${deb_checksum[@]}" ]];
        then
            echo "WARNING! ${list_pkgs_installed[$i]}_${list_versions_installed[$i]}_all.deb checksum doesn't matches"
            echo "Backup will not be restored if there are errors in install"
            NO_BACKUPS_EXIST="1"
        fi
    fi
}

check_debs_versions_backup() {
    for i in "${!list_pkgs_installed[@]}"
    do
        result=($(sshpass -p $PASSWORD ssh $NOKEY $USER@$ip "find /var/cache/apt/archives/ -type f -name '${list_pkgs_installed[$i]}_${list_versions_installed[$i]}_all.deb'"))
        check_deb_file_exist
        check_checksum
    done
}

verify_backups_all_blocks() {
    for ip in "${ips[@]}"
    do
        list_pkgs_installed=($(sshpass -p $PASSWORD ssh $NOKEY $USER@$ip dpkg -l | grep wise-* | awk '{print $2}'))
        list_versions_installed=($(sshpass -p $PASSWORD ssh $NOKEY $USER@$ip dpkg -l | grep wise-* | awk '{print $3}'))
        check_debs_versions_backup
    done
}

remove_old_folder_update() {
    for ip in "${ips[@]}"
    do
        sshpass -p $PASSWORD ssh $NOKEY $USER@$ip 'rm -rf /test_PO/wiseflyUpdate'
    done
}

copy_new_folder_update() {
    echo "Copying new wiseflyUpdate..."
    for ip in "${ips[@]}"
    do
        sshpass -p $PASSWORD scp -r $NOKEY $USB_VOLUME/$UPDATE_DIR `
`$USER@$ip:/test_PO/ &>/dev/null || { echo "[$ip] Failed to copy"; status_result_file "FAIL. [$ip] Failed to copy"; exit 77; }
    done
    echo "All files copied to /test_PO/$UPDATE_DIR"
}

remember_installed_packages() {
    if sshpass -p $PASSWORD ssh $NOKEY $USER@$ip 'stat /tmp/packages.txt &>/dev/null'
    then
        sshpass -p $PASSWORD ssh $NOKEY $USER@$ip "rm /tmp/packages.txt"
    fi
    
    installed_pkgs=($(sshpass -p $PASSWORD ssh $NOKEY $USER@$ip dpkg -l | grep wise-* | awk '{print $2}'))
    installed_versions=($(sshpass -p $PASSWORD ssh $NOKEY $USER@$ip dpkg -l | grep wise-* | awk '{print $3}'))
    
    for i in "${!installed_pkgs[@]}"
    do
        sshpass -p $PASSWORD ssh $NOKEY $USER@$ip "echo ${installed_pkgs[$i]} ${installed_versions[$i]} >> /tmp/packages.txt"
    done
}

check_conformity_usb() {
    for i in "${!list_usb_pkgs[@]}";
    do
        if [[ "${list_usb_pkgs[$i]}" = "$pkg" ]];
        then
            echo "$USB_VOLUME: ${list_usb_pkgs[$i]} ${list_usb_pkgs_ver[$i]}"
        fi
    done
}

check_conformity_block() {
    if [[ "$NUM_BLOCK" > "$num_blocks" ]];
    then
        echo "Error. Number of blocks changed"
        status_result_file "${list_names[$NUM_NAME]} - FAIL. Number of blocks changed"
        exit 1
    fi
}

get_old_configuration() {
    if sshpass -p $PASSWORD ssh $NOKEY $USER@${list_blocks[$NUM_INDEX_ERROR]} 'stat /tmp/main.json &>/dev/null'
    then
        old_configuration=$(sshpass -p $PASSWORD ssh $NOKEY $USER@${list_blocks[$NUM_INDEX_ERROR]} cat /tmp/main.json | grep '"configuration"' | awk '{print $3}' | tr -d \",)
    else
        echo "WARNING! Old configuration wasn't exist. Given configuration from $CONFIG_FILE"
        old_configuration=${list_configurations[$NUM_INDEX_ERROR]}
    fi
}

restore_all() {
    old_packages=($(sshpass -p $PASSWORD ssh $NOKEY $USER@${list_blocks[$NUM_INDEX_ERROR]} cat /tmp/packages.txt | awk '{print $1}'))
    old_versions=($(sshpass -p $PASSWORD ssh $NOKEY $USER@${list_blocks[$NUM_INDEX_ERROR]} cat /tmp/packages.txt | awk '{print $2}'))
    
    for i in "${!old_packages[@]}"
    do
        if [[ "${old_packages[$i]}" == "wise-data-ima" ]];
        then
            get_old_configuration
            result=$(echo -e $old_configuration | sshpass -p $PASSWORD ssh $NOKEY $USER@${list_blocks[$NUM_INDEX_ERROR]} "dpkg -i --force-confnew /var/cache/apt/archives/${old_packages[$i]}_${old_versions[$i]}_all.deb" 2>&1)
            echo "$result" >> "$log_file"
        else
            result=$(sshpass -p $PASSWORD ssh $NOKEY $USER@${list_blocks[$NUM_INDEX_ERROR]} "dpkg -i --force-confnew /var/cache/apt/archives/${old_packages[$i]}_${old_versions[$i]}_all.deb" 2>&1)
            echo "$result" >> "$log_file"
        fi
    done
}

reduce_num_index_error() {
    NUM_INDEX_ERROR=$(($NUM_BLOCK-1))
}

reduce_num_block() {
    NUM_BLOCK=$(($NUM_BLOCK-1))
}

print_install_backup() {
    echo "-----------------------"
    echo "Backup on ${list_blocks[$NUM_INDEX_ERROR]}"
    echo "-----------------------"
}

determine_backup_block() {
    print_install_backup
    restore_all
    status_result_file "${list_names[$NUM_NAME]} - BACKUP OK"
}

install_backup() {
    reduce_num_index_error
    while [ "$NUM_BLOCK" != "0" ];
    do
        determine_backup_block
        reduce_num_block
        reduce_num_index_error
    done
}

clear_tmp() {
    for block in "${list_blocks[@]}"
    do
        sshpass -p $PASSWORD ssh $NOKEY $USER@$block "rm /tmp/*"
    done
}

restoring_backup() {
    echo "Restoring backup..."
    install_backup
    clear_tmp
    log_separator
    
    exit 1
}

check_backups_exist() {
    if [[ "$NO_BACKUPS_EXIST" == "1" ]];
    then
        echo "Error. Some blocks were missing backups"
        status_result_file "${list_names[$NUM_NAME]} - FAIL. Some blocks were missing backups"
        exit 1
    fi
}

check_status_error() {
    if [[ $status > 0 ]];
    then
        echo "PACKAGE HAS ERROR!!!"
        status_result_file "${list_names[$NUM_NAME]} - FAIL"
        check_backups_exist
        restoring_backup
    fi
}

copy_main_config() {
    if sshpass -p $PASSWORD ssh $NOKEY $USER@$ip 'stat /home/data/data_ima_23_27/config/main.json &>/dev/null'
    then
        sshpass -p $PASSWORD ssh $NOKEY $USER@$ip 'mkdir -p /tmp'
        sshpass -p $PASSWORD ssh $NOKEY $USER@$ip 'cp /home/data/data_ima_23_27/config/main.json /tmp'
    fi
}

define_block_pkgs() {
    if [[ "$TYPE_BLOCK" == "MFI" ]];
    then
        BLOCK_PKGS=("${MFI_PKGS[@]}")
    elif [[ "$TYPE_BLOCK" == "PNS" ]];
    then
        BLOCK_PKGS=("${PNS_PKGS[@]}")
    else
        echo "Error. There is no type"
        status_result_file "${list_names[$NUM_NAME]} - FAIL. There is no type"
        exit 1
    fi
}

install_block() {
    for pkg in "${BLOCK_PKGS[@]}"
    do
        check_conformity_usb
        echo "Installing..."
        if [[ "$pkg" == "wise-data-ima" ]];
        then
            copy_main_config
            result=$(echo -e ${list_configurations[$NUM_CONFIGURATION]} | sshpass -p $PASSWORD ssh $NOKEY $USER@$ip "dpkg -i --force-confnew /test_PO/wiseflyUpdate/debs/$TYPE_BLOCK/${pkg}_*_all.deb" 2>&1)
            status=$?
        else
            result=$(sshpass -p $PASSWORD ssh $NOKEY $USER@$ip "dpkg -i --force-confnew /test_PO/wiseflyUpdate/debs/$TYPE_BLOCK/${pkg}_*_all.deb" 2>&1)
            status=$?
        fi
        echo "$result" >> "$log_file"
        check_conformity_block
        check_status_error
        echo "Done."
    done
}

log_separator() {
    echo "" >> $log_file
    echo "---------------------------------------------" >> $log_file
    echo "" >> $log_file
}

print_install_on_block() {
    echo "------------------------"
    echo "Install on $ip"
    echo "------------------------"
}

install() {
    print_install_on_block
    define_block_pkgs
    install_block "${#BLOCK_PKGS[@]}" "${BLOCK_PKGS[@]}"
    log_separator
    status_result_file "${list_names[$NUM_NAME]} - OK"
}

create_log_file() {
    if [[ ! -e $USB_VOLUME/$UPDATE_DIR/logs/${list_names[$NUM_NAME]}.txt ]];
    then
        mkdir -p $USB_VOLUME/$UPDATE_DIR/logs
        touch $USB_VOLUME/$UPDATE_DIR/logs/${list_names[$NUM_NAME]}.txt
    fi
}

set_current_block() {
    NUM_BLOCK=$((NUM_BLOCK+1))
    NUM_NAME=$((NUM_NAME+1))
    NUM_CONFIGURATION=$((NUM_CONFIGURATION+1))
    TYPE_BLOCK="${list_names[$NUM_NAME]:0:3}"
    
    if [[ -z "$TYPE_BLOCK" ]];
    then
        echo "Error. There is no string in file or type for this block"
        status_result_file "${list_names[$NUM_NAME]} - FAIL. There is no string in file or type for this block"
        exit 1
    fi
}

create_list_usb() {
    mapfile -t list_usb_pkgs <  <(for file in $USB_VOLUME/$UPDATE_DIR/debs/$TYPE_BLOCK/*.deb; do dpkg-deb -W $file; done | awk '{print $1}')
    mapfile -t list_usb_pkgs_ver <  <(for file in $USB_VOLUME/$UPDATE_DIR/debs/$TYPE_BLOCK/*.deb; do dpkg-deb -W $file; done | awk '{print $2}')
}

set_current_ip() {
    ip=${list_blocks[$NUM_NAME]}
}

set_debs_path() {
    debs_path=/test_PO/$UPDATE_DIR/debs/$TYPE_BLOCK
}

set_log_file_name() {
    log_file=$USB_VOLUME/$UPDATE_DIR/logs/${list_names[$NUM_NAME]}.txt
}

copy_debs_to_cache() {
    sshpass -p $PASSWORD ssh $NOKEY $USER@$ip "mkdir -p /var/cache/apt/archives/ && `
`cp -rf /test_PO/wiseflyUpdate/debs/$TYPE_BLOCK/* /var/cache/apt/archives/"
}

preparation() {
    set_current_block
    create_list_usb
    create_log_file
    set_current_ip
    set_debs_path
    set_log_file_name
    copy_debs_to_cache
    remember_installed_packages
}

do_install() {
    for block in "${list_blocks[@]}"
    do
        preparation
        install
    done
}

check_usb_volume_mounted
recreate_result_file
check_file_packages_exist
check_file_packages_not_empty
check_config_file_exist
check_config_file_not_empty
create_configuration_lists
check_type_exist
create_packages_lists
check_file_packages_conformity
count_num_blocks
identify_blocks "${#ips[@]}" "${ips[@]}"
verify_backups_all_blocks
remove_old_folder_update
copy_new_folder_update
do_install
clear_tmp

exit 0
