#!/bin/sh

. /etc/initrd.d/00-common.sh
. /etc/initrd.d/00-fsdev.sh
. /etc/initrd.d/00-devmgr.sh
. /etc/initrd.d/00-splash.sh

is_zfs() {
    # Note: this only works after zfs_real_root_init
    #       (thus, only after real_root_init)
    [ "${USE_ZFS}" = "1" ] && return 0
    return 1
}

# This piece of information can be used by external
# functions to return the default filesystem type
# for zfs members.
zfs_member_fstype() {
    echo "zfs_member"
}

is_zfs_fstype() {
    local fstype="${1}"
    [ "${fstype}" = "$(zfs_member_fstype)" ] && return 0
    return 1
}

zfs_real_root_init() {
    case "${REAL_ROOT}" in
        ZFS=*)
            ZFS_POOL=${REAL_ROOT#*=}
            ZFS_POOL=${ZFS_POOL%%/*}
            USE_ZFS=1
        ;;
        ZFS)
            USE_ZFS=1
        ;;
    esac

    # Verify that zfs support has been compiled in
    if [ "${USE_ZFS}" = "1" ]; then
        for i in /sbin/zfs /sbin/zpool; do
            if [ ! -x "${i}" ]; then
                USE_ZFS=0
                bad_msg 'Aborting use of zfs because ${i} not found!'
                break
            fi
        done
    fi
}

# This helper function is to be called using _call_func_timeout.  This
# works around the inability of busybox modprobe to handle complex
# module dependencies. This also enables us to wait a reasonable
# amount of time until /dev/zfs appears.
wait_for_zfs() {
    while [ ! -c /dev/zfs ]; do modprobe zfs 2> /dev/null; done;
}

_call_func_timeout() {
    local func=$1 timeout=$2 pid watcher

    ( ${func} ) & pid=$!
    ( sleep ${timeout} && kill -HUP ${pid} ) 2>/dev/null & watcher=$!
    if wait ${pid} 2>/dev/null; then
        kill -HUP $watcher 2> /dev/null
        wait $watcher 2>/dev/null
        return 1
    fi

    return 0
}

zfs_start_volumes() {
    # is ZFS enabled?
    is_zfs || return 0

    # Avoid race involving asynchronous module loading
    if _call_func_timeout wait_for_zfs 5; then
        bad_msg "Cannot import ZFS pool because /dev/zfs is missing"

    elif [ -z "${ZFS_POOL}" ]; then
        good_msg "Importing ZFS pools"

        zpool import -N -a ${ZPOOL_FORCE}
        if [ "${?}" = "0" ]; then
            good_msg "Importing ZFS pools succeeded"
        else
            warn_msg "Imported ZFS pools failed"
        fi

    else
        local pools=$(zpool list -H -o name ${ZFS_POOL} 2>&1)
        if [ "${pools}" = "${ZFS_POOL}" ]; then
            good_msg "ZFS pool ${ZFS_POOL} already imported."

            if [ -n "${CRYPT_ROOTS}" ] || [ -n "${CRYPT_SWAPS}" ]; then
                good_msg "LUKS detected. Reimporting ${ZFS_POOL}"
                zpool export -f "${ZFS_POOL}"
                zpool import -N ${ZPOOL_FORCE} "${ZFS_POOL}"
            fi
        else
            good_msg "Importing ZFS pool ${ZFS_POOL}"
            zpool import -N ${ZPOOL_FORCE} "${ZFS_POOL}"

            if [ "${?}" = "0" ]; then
                good_msg "Import of ${ZFS_POOL} succeeded"
            else
                warn_msg "Import of ${ZFS_POOL} failed"
            fi
        fi
    fi

    is_udev && udevadm settle
}

# Load potentially encrypted zfs filesystems or volumes
# REQUIRES >=sys-fs/zfs-0.8 or 9999 version after Jan 2017
_keyload_exec() {
    local dataset_dev="${1}"
    local ply_cmd="${2}" # command for use when plymouth is active
    local tty_cmd="${3}" # command for use without plymouth
    local do_ask="${4}"  # whether we need a passphrase at all

    if [ "${CRYPT_SILENT}" = "1" -o "${do_ask}" = "0" ]; then
        eval ${tty_cmd} >/dev/null 2>/dev/null
    else
        ask_for_password --ply-tries 5 \
            --ply-cmd "${ply_cmd}" \
            --ply-prompt "Encryption password (${dataset_dev}): " \
            --tty-tries 5 \
            --tty-cmd "${tty_cmd}" || return 1
        return 0
    fi
}
zfs_loadkey() {
    local zfs_loads="${ZFS_LOADS}"
    for dataset in ${zfs_loads}; do

        good_msg "Loading key for dataset ${dataset}..."

        # split $dataset variable into array; which means path shall
        # not contain ':' or space
        #
        # zfs_load=* should be in order of:
        #    dataset_dev:dataset_keydev:dataset_keydev_fs:dataset_key:dataset_keydev_flags
        # dataset_dev: dataset path of loading dataset
        # dataset_keydev: device to be mounted on /mnt/key to load the key
        # dataset_keydev_fs: filesystem type of keydev
        # dataset_key: path to key file
        # dataset_keydev_flags: options to mount keydev
        # If key device is a ZFS filesystem whose mountpoint=* is not legacy
        # then `zfsutil` MUST be passed as a mount option
        dataset_dev=$(echo ${dataset}|awk '{split($0,a,":")}END{print(a[1])}')
        dataset_keydev=$(echo ${dataset}|awk '{split($0,a,":")}END{print(a[2])}')
        dataset_keydev_fs=$(echo ${dataset}|awk '{split($0,a,":")}END{print(a[3])}')
        dataset_key=$(echo ${dataset}|awk '{split($0,a,":")}END{print(a[4])}')
        dataset_keydev_flags=$(echo ${dataset}|awk '{split($0,a,":")}END{print(a[5])}')

        # import the pool if not yet imported
	local ZFS_POOL_old="${ZFS_POOL}"
        local CRYPT_ROOTS_old="${CRYPT_ROOTS}"
        local CRYPT_SWAPS_old="${CRYPT_SWAPS}"
        ZFS_POOL="${dataset_dev%%/*}"
        CRYPT_ROOTS=""
        CRYPT_SWAPS=""
        zfs_start_volumes
	ZFS_POOL="${ZFS_POOL_old}"
        CRYPT_ROOTS="${CRYPT_ROOTS_old}"
        CRYPT_SWAPS="${CRYPT_SWAPS_old}"

        local dev_error=0 key_error=0 keydev_error=0
        while true; do
            local passphrase_needed="1"
            local gpg_ply_cmd=""
            local gpg_tty_cmd=""
            local mntkey="/mnt/key" loadkey_opts=""

            # Handling errors while loading dataset
            local any_error=
            [ "${dev_error}" = "1" ] && any_error=1
            [ "${key_error}" = "1" ] && any_error=1
            [ "${keydev_error}" = "1" ] && any_error=1

            # if crypt_silent=1 and some error occurs, bail out.
            if [ "${CRYPT_SILENT}" = "1" ] && [ -n "${any_error}" ]; then
                bad_msg "Failed to load ZFS encryption key"
                exit_st=1
                break
            fi

            if [ "${dev_error}" = "1" ]; then
                prompt_user "dataset_dev" "${dataset_dev}"
                dev_error=0
                continue
            fi

            #if [ "${key_error}" = "1" ]; then
            #    prompt_user "dataset_key" "${dataset_dev} key"
            #    key_error=0
            #    continue
            #fi

            #if [ "${keydev_error}" = "1" ]; then
            #    prompt_user "dataset_keydev" "${dataset_dev} key device"
            #    prompt_user "dataset_keydev_fs" "${dataset_dev} key device filesystem"
            #    prompt_user "dataset_keydev_flags" "${dataset_dev} key device mount flags"
            #    keydev_error=0
            #    continue
            #fi

	    if [ "${any_error}" = "1" ]; then

	        local dataset_key_settings="${dataset_keydev}:${dataset_keydev_fs}:${dataset_key}:${dataset_keydev_flags}"
		prompt_user "dataset_key_settings" "${dataset_dev} key"
                dataset_keydev=$(echo ${dataset_key_settings}|awk '{split($0,a,":")}END{print(a[1])}')
                dataset_keydev_fs=$(echo ${dataset_key_settings}|awk '{split($0,a,":")}END{print(a[2])}')
                dataset_key=$(echo ${dataset_key_settings}|awk '{split($0,a,":")}END{print(a[3])}')
                dataset_keydev_flags=$(echo ${dataset_key_settings}|awk '{split($0,a,":")}END{print(a[4])}')
                key_error=0
                keydev_error=0
		continue
            fi

            # Checking if encryption is enabled on such device
            local if_encrypted=$(zfs get -Ho value keystatus ${dataset_dev}) || {
                bad_msg "Cannot read keystatus info for ${dataset_dev}"
                dev_error=1
                continue;
            }
            if [ "${if_encrypted}" != "unavailable" ]; then
                bad_msg "${dataset_dev} does not require loading"
                break
            fi

            # Handle keys
            if [ -n "${dataset_keydev}" ]; then
                local real_dataset_keydev="${dataset_keydev}"
                # handle mount flags
                local real_dataset_keydev_flags="ro"
                if [ -n "${dataset_keydev_flags}" ]; then
                    real_dataset_keydev_flags="${real_dataset_keydev_flags},${dataset_keydev_flags}"
                fi
                local real_dataset_keydev_fs=""
                if [ -n "${dataset_keydev_fs}" ]; then
                    real_dataset_keydev_fs="-t ${dataset_keydev_fs}"
                fi

                if [ ! -e "${mntkey}${dataset_key}" ]; then
                    real_dataset_keydev=$(find_real_device "${dataset_keydev}")
                    good_msg "Using key device ${real_dataset_keydev}."

                    if [ ! -b "${real_dataset_keydev}" ]; then
                        # Check if keydev is zfs
                        if [ "${dataset_keydev_fs}" = "zfs" ]; then
                            # import the pool if not yet imported
			    local ZFS_POOL_old="${ZFS_POOL}"
	                    local CRYPT_ROOTS_old="${CRYPT_ROOTS}"
	                    local CRYPT_SWAPS_old="${CRYPT_SWAPS}"
	                    ZFS_POOL="${dataset_keydev%%/*}"
	                    CRYPT_ROOTS=""
	                    CRYPT_SWAPS=""
	                    zfs_start_volumes
			    ZFS_POOL="${ZFS_POOL_old}"
	                    CRYPT_ROOTS="${CRYPT_ROOTS_old}"
	                    CRYPT_SWAPS="${CRYPT_SWAPS_old}"
                            # handle non-legacy mountpoints
                            dataset_keydev_mountpoint=$(zfs get -Ho value mountpoint ${dataset_keydev}) || {
                                bad_msg "Cannot get ZFS mountpoint for key device ${dataset_keydev}"
                                keydev_error=1
                                continue
                            }
                            if [ "${dataset_keydev_mountpoint}" != "legacy" ]; then
                                real_dataset_keydev_flags="${real_dataset_keydev_flags},zfsutil"
                            fi

                        elif [ "${dataset_keydev#/dev/zvol/}" != "${dataset_keydev}" ]; then
                            # keydev is a zpool volume
                            # try to load its master pool
			    local ZFS_POOL_old="${ZFS_POOL}"
                            local keydev_dataset="${dataset_keydev#/dev/zvol/}"
	                    local CRYPT_ROOTS_old="${CRYPT_ROOTS}"
	                    local CRYPT_SWAPS_old="${CRYPT_SWAPS}"
	                    ZFS_POOL="${keydev_dataset%%/*}"
	                    CRYPT_ROOTS=""
	                    CRYPT_SWAPS=""
	                    zfs_start_volumes
			    ZFS_POOL="${ZFS_POOL_old}"
	                    CRYPT_ROOTS="${CRYPT_ROOTS_old}"
	                    CRYPT_SWAPS="${CRYPT_SWAPS_old}"
                            real_dataset_keydev=$(find_real_device "${dataset_keydev}")
                            if [ ! -b "${real_dataset_keydev}" ]; then
                                keydev_error=1
                                continue
                            fi

                        else
                            bad_msg "Insert device ${dataset_keydev} for ${dataset_dev}"
                            bad_msg "You have 10 seconds..."
                            local count=10
                            while [ ${count} -gt 0 ]; do
                                count=$((count-1))
                                sleep 1

                                real_dataset_keydev=$(find_real_device "${dataset_keydev}")
                                [ ! -b "${real_dataset_keydev}" ] || {
                                    good_msg "Device ${real_dataset_keydev} detected."
                                    break;
                                }
                            done
                            if [ ! -b "${real_dataset_keydev}" ]; then
                                export CRYPT_ZFS_KEYDEV="${dataset_keydev}"
                                media_find "key" "${dataset_key}" "CRYPT_ZFS_KEYDEV" "${mntkey}" $(device_list)
                                dataset_keydev="${CRYPT_ZFS_KEYDEV}"
                                real_dataset_keydev=$(find_real_device "${dataset_keydev}")
                                if [ ! -b "${real_dataset_keydev}" ]; then
                                    keydev_error=1
                                    bad_msg "Device ${dataset_keydev} not found."
                                    continue
                                fi

                                # continue otherwise will mount keydev which is
                                # mounted by bootstrap
                                continue
                            fi
                        fi
                    fi

                    # At this point a device was recognized, now let's see
                    # if the key is there
                    mkdir -p "${mntkey}"  # ignore

		    local mount_command="mount -n ${real_dataset_keydev_fs} -o ${real_dataset_keydev_flags} ${real_dataset_keydev} ${mntkey}"
		    good_msg "${mount_command}"
		    eval "${mount_command}" || {
		        keydev_error=1
                        bad_msg "Mounting of device ${real_dataset_keydev} failed."
                        continue;
                    }

                   # mount -n ${real_dataset_keydev_fs} \
                   #     -o ${real_dataset_keydev_flags} \
                   #     "${real_dataset_keydev}" \
                   #     "${mntkey}" || {
                   #     keydev_error=1
                   #     bad_msg "Mounting of device ${real_dataset_keydev} failed."
                   #     continue;
                   # }

                    good_msg "Removable device ${real_dataset_keydev} mounted."

                    if [ ! -e "${mntkey}${dataset_key}" ]; then
                        umount -n "${mntkey}"
                        key_error=1
                        keydev_error=1
                        bad_msg "${dataset_key} on ${real_dataset_keydev} not found."
                        continue
                    fi
                fi

                # At this point a candidate key exists
                # (either mounted before or not)
                good_msg "${dataset_key} on device ${real_dataset_keydev} found"
                if [ "$(echo ${dataset_key} | grep -o '.gpg$')" = ".gpg" ] && \
                    [ -e /usr/bin/gpg ]; then

                    # TODO(lxnay): WTF is this?
                    [ -e /dev/tty ] && mv /dev/tty /dev/tty.org
                    mknod /dev/tty c 5 1

                    loadkey_opts="${loadkey_opts} -L prompt"
                    # if plymouth not in use, gpg reads keyfile passphrase...
                    gpg_tty_cmd="/usr/bin/gpg --logger-file /dev/null"
                    gpg_tty_cmd="${gpg_tty_cmd} --quiet --decrypt ${mntkey}${dataset_key} | "
                    # but when plymouth is in use, keyfile passphrase piped in
                    gpg_ply_cmd="/usr/bin/gpg --logger-file /dev/null"
                    gpg_ply_cmd="${gpg_ply_cmd} --quiet --passphrase-fd 0 --batch --no-tty"
                    gpg_ply_cmd="${gpg_ply_cmd} --decrypt ${mntkey}${dataset_key} | "
                else
                    loadkey_opts="${loadkey_opts} -L file://${mntkey}${dataset_key}"
                    passphrase_needed="0" # keyfile not itself encrypted
                fi
            else
                loadkey_opts="${loadkey_opts} -L prompt"
                passphrase_needed="1"
            fi

            # At this point, keyfile or not, we're ready!
            local ply_cmd="${gpg_ply_cmd} zfs load-key"
            local tty_cmd="${gpg_tty_cmd} zfs load-key"
            ply_cmd="${ply_cmd} ${loadkey_opts} ${dataset_dev}"
            tty_cmd="${tty_cmd} ${loadkey_opts} ${dataset_dev}"
            # send to a temporary shell script, so plymouth can
            # invoke the pipeline successfully
            local ply_cmd_file="$(mktemp -t "ply_cmd.XXXXXX")"
            printf '#!/bin/sh\n%s\n' "${ply_cmd}" > "${ply_cmd_file}"
            chmod 500 "${ply_cmd_file}"
            _keyload_exec "${dataset_dev}" "${ply_cmd_file}" "${tty_cmd}" "${passphrase_needed}"
            local ret="${?}"
            rm -f "${ply_cmd_file}"

            # TODO(lxnay): WTF is this?
            [ -e /dev/tty.org ] \
                && rm -f /dev/tty \
                && mv /dev/tty.org /dev/tty
            umount -l "${mntkey}" 2>/dev/null >/dev/null
            rmdir "${mntkey}" 2>/dev/null >/dev/null


            if [ "${ret}" = "0" ]; then
                good_msg "${dataset_dev} successfully loaded"
                break
            fi

            bad_msg "Failed to load dataset ${dataset_dev}"
            dev_error=1
            key_error=1
            keydev_error=1

        done

    done

    return ${exit_st}
}

# Initialize the zfs root filesystem device and
# tweak ${REAL_ROOT}. In addition, set ${ZFS_POOL}
# for later use.
# Return 0 if initialization is successful.
zfs_rootdev_init() {
    local root_dev="${REAL_ROOT#*=}"
    ZFS_POOL="${root_dev%%/*}"

    if [ "${root_dev}" != "ZFS" ]; then
        local ztype=$(zfs get type -o value -H "${root_dev}")
        if [ "${ztype}" = "filesystem" ]; then
            REAL_ROOT="${root_dev}"
            good_msg "Detected zfs root: ${REAL_ROOT}"
            return 0
        else
            bad_msg "${root_dev} is not a zfs filesystem"
            return 1
        fi
    fi

    local bootfs=$(zpool list -H -o bootfs)
    [ "${bootfs}" = "-" ] && return 1

    for i in ${bootfs}; do
        if zfs get type "${i}" > /dev/null; then
            REAL_ROOT="${i}"
            good_msg "Detected zfs bootfs root: ${REAL_ROOT}"
            return 0
        fi
    done
    return 1
}

zfs_get_real_root_mount_flags() {
    local flags=rw,zfsutil
    local zmtype=$(zfs get -H -o value mountpoint "${REAL_ROOT}")
    [ "${zmtype}" = "legacy" ] && flags=rw
    echo "${flags}"
}
