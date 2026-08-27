#ifndef PQCLI_COMMANDS_H
#define PQCLI_COMMANDS_H

int cmd_help(int argc, char **argv);
int cmd_version(int argc, char **argv);
int cmd_list_algs(int argc, char **argv);
int cmd_doctor(int argc, char **argv);

int cmd_genkey(int argc, char **argv);
int cmd_list_keys(int argc, char **argv);
int cmd_export(int argc, char **argv);
int cmd_import(int argc, char **argv);
int cmd_use(int argc, char **argv);
int cmd_info(int argc, char **argv);
int cmd_rm_key(int argc, char **argv);
int cmd_passwd(int argc, char **argv);
int cmd_config(int argc, char **argv);
int cmd_fingerprint(int argc, char **argv);
int cmd_backup(int argc, char **argv);
int cmd_restore(int argc, char **argv);

int cmd_keyring_list(int argc, char **argv);
int cmd_keyring_add(int argc, char **argv);
int cmd_keyring_remove(int argc, char **argv);
int cmd_keyring_trust(int argc, char **argv);
int cmd_keyring_verify(int argc, char **argv);

int cmd_encrypt(int argc, char **argv);
int cmd_decrypt(int argc, char **argv);
int cmd_sign(int argc, char **argv);
int cmd_verify(int argc, char **argv);
int cmd_inspect(int argc, char **argv);
int cmd_reencrypt(int argc, char **argv);
int cmd_wipe(int argc, char **argv);

void pq_profile_algs(const char *profile, const char **kem, const char **sig);

#endif
