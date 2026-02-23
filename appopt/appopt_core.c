#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/cpumask.h>
#include <linux/cpuset.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/sort.h>
#include <linux/namei.h>
#include <linux/string_helpers.h>
#include <linux/mm.h>




static char *strtrim(char *s)
{
    char *end;
    while (isspace(*s)) s++;
    if (*s == 0) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    *(end + 1) = 0;
    return s;
}

static int appopt_fnmatch(const char *pattern, const char *string)
{
    const char *p = pattern;
    const char *s = string;

    while (*p) {
        if (*p == '*') {
            p++;
            if (!*p) {
                return 0; // * at end matches everything
            }
            while (*s) {
                if (appopt_fnmatch(p, s) == 0) {
                    return 0;
                }
                s++;
            }
            return 1;
        } else if (*p == '?') {
            if (!*s) {
                return 1;
            }
            p++;
            s++;
        } else if (*p != *s) {
            return 1;
        } else {
            p++;
            s++;
        }
    }

    return !*s;
}


#define APPOPT_VERSION "1.6.3"
#define APPOPT_CONFIG_PATH "/data/adb/applist.prop"
#define APPOPT_BASE_CPUSET "/dev/cpuset/system-control-apps"
#define APPOPT_MAX_PKG_LEN 128
#define APPOPT_MAX_THREAD_LEN 32
#define APPOPT_INITIAL_PKG_CAPACITY 2560
#define APPOPT_INITIAL_RULE_CAPACITY 8192
#define APPOPT_INITIAL_WILDCARD_CAPACITY 128

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AppOpt Team");
MODULE_DESCRIPTION("Application CPU Affinity Optimizer");
MODULE_VERSION(APPOPT_VERSION);

static struct task_struct *appopt_thread;
static int appopt_interval = 2;
static bool appopt_running = false;

static struct proc_dir_entry *appopt_proc_dir;
static struct proc_dir_entry *appopt_status_entry;

struct appopt_affinity_rule {
    char pkg[APPOPT_MAX_PKG_LEN];
    char thread[APPOPT_MAX_THREAD_LEN];
    char cpuset_dir[256];
    struct cpumask cpus;
    bool is_wildcard;
    int priority;
};

struct appopt_thread_info {
    pid_t tid;
    char name[APPOPT_MAX_THREAD_LEN];
    char cpuset_dir[256];
    struct cpumask cpus;
};

struct appopt_process_info {
    pid_t pid;
    char pkg[APPOPT_MAX_PKG_LEN];
    char base_cpuset[128];
    struct cpumask base_cpus;
    struct appopt_thread_info *threads;
    size_t num_threads;
    size_t threads_cap;
    struct appopt_affinity_rule **thread_rules;
    size_t num_thread_rules;
    size_t thread_rules_cap;
};

struct appopt_cpu_topology {
    struct cpumask present_cpus;
    char present_str[128];
    char mems_str[32];
    bool cpuset_enabled;
    int base_cpuset_fd;
};

struct appopt_config {
    struct appopt_affinity_rule *rules;
    size_t num_rules;
    struct appopt_affinity_rule **wildcard_rules;
    size_t num_wildcard_rules;
    time_t mtime;
    struct appopt_cpu_topology topo;
    char **pkgs;
    size_t num_pkgs;
    char config_file[4096];
    char cpuset_base[256];
};

static struct appopt_config *appopt_current_config;

static int appopt_parse_cpu_ranges(const char *spec, struct cpumask *set, const struct cpumask *present)
{
    char *copy, *s, *end;
    unsigned long a, b, i;
    int ret = 0;

    if (!spec) {
        cpumask_clear(set);
        return 0;
    }

    copy = kstrdup(spec, GFP_KERNEL);
    if (!copy) {
        return -ENOMEM;
    }

    s = copy;

    while (*s) {
        a = simple_strtoul(s, &end, 10);
        if (end == s) {
            s++;
            continue;
        }

        b = a;
        if (*end == '-') {
            s = end + 1;
            b = simple_strtoul(s, &end, 10);
            if (end == s) {
                b = a;
            }
        }

        if (a > b) {
            ret = -EINVAL;
            goto out;
        }

        for (i = a; i <= b && i < nr_cpu_ids; i++) {
            if (present && !cpumask_test_cpu(i, present)) {
                ret = -EINVAL;
                goto out;
            }
            cpumask_set_cpu(i, set);
        }

        s = (*end == ',') ? end + 1 : end;
    }

out:
    kfree(copy);
    return ret;
}



static int appopt_init_cpu_topo(struct appopt_cpu_topology *topo)
{
    int i;
    int cpu_count;
    char cpu_range[128];

    cpumask_clear(&topo->present_cpus);
    topo->cpuset_enabled = false;
    topo->base_cpuset_fd = -1;

    // 使用内核API获取CPU数量
    cpu_count = num_possible_cpus();
    pr_info("AppOpt: detected %d CPUs using num_possible_cpus()\n", cpu_count);

    // 设置所有可能的CPU到cpumask中
    for (i = 0; i < cpu_count; i++) {
        if (cpu_possible(i)) {
            cpumask_set_cpu(i, &topo->present_cpus);
        }
    }

    // 生成CPU范围字符串，如 "0-3"
    if (cpu_count == 1) {
        snprintf(cpu_range, sizeof(cpu_range), "0");
    } else {
        snprintf(cpu_range, sizeof(cpu_range), "0-%d", cpu_count - 1);
    }
    strncpy(topo->present_str, cpu_range, sizeof(topo->present_str) - 1);
    topo->present_str[sizeof(topo->present_str) - 1] = '\0';

    strncpy(topo->mems_str, "0", sizeof(topo->mems_str) - 1);
    topo->mems_str[sizeof(topo->mems_str) - 1] = '\0';

    return 0;
}

static int appopt_calculate_rule_priority(const char *thread_pattern)
{
    int priority = 0;
    size_t len;
    const char *p;
    int non_wildcard_chars = 0;
    bool has_range = false;
    bool has_single_wildcard = false;
    bool has_star = false;

    if (!thread_pattern || !*thread_pattern) {
        return 200;
    }

    len = strlen(thread_pattern);
    p = thread_pattern;

    if (strchr(p, '*') == NULL && strchr(p, '?') == NULL && strchr(p, '[') == NULL) {
        return 1000 + len;
    }

    while (*p) {
        if (*p == '[') {
            has_range = true;
        } else if (*p == '?') {
            has_single_wildcard = true;
        } else if (*p == '*') {
            has_star = true;
        } else {
            non_wildcard_chars++;
        }
        p++;
    }

    if (has_range) {
        priority = 500 + non_wildcard_chars;
    } else if (has_single_wildcard) {
        priority = 300 + non_wildcard_chars;
    } else if (has_star) {
        priority = 100 + non_wildcard_chars;
    }

    return priority;
}

static struct appopt_config *appopt_load_config(const char *config_file, struct appopt_cpu_topology *topo)
{
    struct file *file;
    char *buf;
    ssize_t read;
    struct appopt_config *cfg;
    struct appopt_affinity_rule *rules;
    size_t rules_capacity;
    size_t num_rules;
    struct appopt_affinity_rule **wildcard_rules;
    size_t wildcard_capacity;
    size_t num_wildcard_rules;
    char **pkgs;
    size_t pkgs_capacity;
    size_t num_pkgs;
    struct kstat st;
    int ret;
    char *line, *next_line, *p, *eq, *key, *value, *br, *thread, *pkg, *eb;
    struct appopt_affinity_rule *rule;
    char cpus_str[128];

    ret = vfs_stat(config_file, &st);
    if (ret != 0) {
        pr_warn("AppOpt: config file not found, creating empty one\n");
        file = filp_open(config_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (!IS_ERR(file)) {
            const char *initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top";
            kernel_write(file, initial_content, strlen(initial_content), &file->f_pos);
            filp_close(file, NULL);
        }
        return NULL;
    }

    file = filp_open(config_file, O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("AppOpt: failed to open config file %s: %ld\n", config_file, PTR_ERR(file));
        return NULL;
    }

    buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        filp_close(file, NULL);
        return NULL;
    }

    cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
    if (!cfg) {
        kfree(buf);
        filp_close(file, NULL);
        return NULL;
    }

    rules = kzalloc(APPOPT_INITIAL_RULE_CAPACITY * sizeof(*rules), GFP_KERNEL);
    if (!rules) {
        kfree(cfg);
        kfree(buf);
        filp_close(file, NULL);
        return NULL;
    }

    wildcard_rules = kzalloc(APPOPT_INITIAL_WILDCARD_CAPACITY * sizeof(*wildcard_rules), GFP_KERNEL);
    if (!wildcard_rules) {
        kfree(rules);
        kfree(cfg);
        kfree(buf);
        filp_close(file, NULL);
        return NULL;
    }

    pkgs = kzalloc(APPOPT_INITIAL_PKG_CAPACITY * sizeof(*pkgs), GFP_KERNEL);
    if (!pkgs) {
        kfree(wildcard_rules);
        kfree(rules);
        kfree(cfg);
        kfree(buf);
        filp_close(file, NULL);
        return NULL;
    }

    rules_capacity = APPOPT_INITIAL_RULE_CAPACITY;
    num_rules = 0;
    wildcard_capacity = APPOPT_INITIAL_WILDCARD_CAPACITY;
    num_wildcard_rules = 0;
    pkgs_capacity = APPOPT_INITIAL_PKG_CAPACITY;
    num_pkgs = 0;

    while ((read = kernel_read(file, buf, PAGE_SIZE - 1, &file->f_pos)) > 0) {
        buf[read] = '\0';
        line = buf;

        while ((next_line = strchr(line, '\n')) != NULL) {
            *next_line = '\0';
            p = strtrim(line);
            if (*p && *p != '#') {
                eq = strchr(p, '=');
                if (eq) {
                    *eq++ = '\0';
                    key = strtrim(p);
                    value = strtrim(eq);

                    br = strchr(key, '{');
                    thread = "";
                    if (br) {
                        *br++ = '\0';
                        eb = strchr(br, '}');
                        if (eb) {
                            *eb = '\0';
                            thread = strtrim(br);
                        }
                    }

                    pkg = strtrim(key);
                    if (strlen(pkg) < APPOPT_MAX_PKG_LEN && strlen(thread) < APPOPT_MAX_THREAD_LEN) {
                        if (num_rules >= rules_capacity) {
                            rules_capacity *= 2;
                            rules = krealloc(rules, rules_capacity * sizeof(*rules), GFP_KERNEL);
                            if (!rules) {
                                goto error;
                            }
                        }

                        rule = &rules[num_rules];
                        strncpy(rule->pkg, pkg, APPOPT_MAX_PKG_LEN - 1);
                        rule->pkg[APPOPT_MAX_PKG_LEN - 1] = '\0';
                        strncpy(rule->thread, thread, APPOPT_MAX_THREAD_LEN - 1);
                        rule->thread[APPOPT_MAX_THREAD_LEN - 1] = '\0';
                        cpumask_clear(&rule->cpus);

                        ret = appopt_parse_cpu_ranges(value, &rule->cpus, &topo->present_cpus);
                        if (ret == 0 && !cpumask_empty(&rule->cpus)) {
                            snprintf(cpus_str, sizeof(cpus_str), "%*pbl", cpumask_pr_args(&rule->cpus));
                            snprintf(rule->cpuset_dir, sizeof(rule->cpuset_dir), "%s", cpus_str);

                            rule->is_wildcard = (strchr(pkg, '*') != NULL || strchr(pkg, '?') != NULL || strchr(pkg, '[') != NULL);
                            rule->priority = appopt_calculate_rule_priority(thread);

                            if (rule->is_wildcard) {
                                if (num_wildcard_rules >= wildcard_capacity) {
                                    wildcard_capacity *= 2;
                                    wildcard_rules = krealloc(wildcard_rules, wildcard_capacity * sizeof(*wildcard_rules), GFP_KERNEL);
                                    if (!wildcard_rules) {
                                        goto error;
                                    }
                                }
                                wildcard_rules[num_wildcard_rules++] = rule;
                            } else {
                                if (num_pkgs >= pkgs_capacity) {
                                    pkgs_capacity *= 2;
                                    pkgs = krealloc(pkgs, pkgs_capacity * sizeof(*pkgs), GFP_KERNEL);
                                    if (!pkgs) {
                                        goto error;
                                    }
                                }
                                pkgs[num_pkgs++] = kstrdup(pkg, GFP_KERNEL);
                            }

                            num_rules++;
                        }
                    }
                }
            }
            line = next_line + 1;
        }
    }

    filp_close(file, NULL);
    kfree(buf);

    if (num_rules == 0) {
        pr_warn("AppOpt: no valid rules loaded\n");
        kfree(pkgs);
        kfree(wildcard_rules);
        kfree(rules);
        kfree(cfg);
        return NULL;
    }

    cfg->rules = rules;
    cfg->num_rules = num_rules;
    cfg->wildcard_rules = wildcard_rules;
    cfg->num_wildcard_rules = num_wildcard_rules;
    cfg->pkgs = pkgs;
    cfg->num_pkgs = num_pkgs;
    cfg->mtime = st.ino;
    memcpy(&cfg->topo, topo, sizeof(*topo));
    strncpy(cfg->config_file, config_file, sizeof(cfg->config_file) - 1);
    cfg->config_file[sizeof(cfg->config_file) - 1] = '\0';
    strncpy(cfg->cpuset_base, APPOPT_BASE_CPUSET, sizeof(cfg->cpuset_base) - 1);
    cfg->cpuset_base[sizeof(cfg->cpuset_base) - 1] = '\0';

    pr_info("AppOpt: loaded %zu rules, %zu packages, %zu wildcard rules\n", num_rules, num_pkgs, num_wildcard_rules);
    return cfg;

error:
    filp_close(file, NULL);
    kfree(buf);
    kfree(pkgs);
    kfree(wildcard_rules);
    kfree(rules);
    kfree(cfg);
    return NULL;
}

static void appopt_free_config(struct appopt_config *cfg)
{
    size_t i;
    if (cfg) {
        if (cfg->rules) {
            kfree(cfg->rules);
        }
        if (cfg->wildcard_rules) {
            kfree(cfg->wildcard_rules);
        }
        if (cfg->pkgs) {
            for (i = 0; i < cfg->num_pkgs; i++) {
                kfree(cfg->pkgs[i]);
            }
            kfree(cfg->pkgs);
        }
        kfree(cfg);
    }
}

static int appopt_compare_rules(const void *a, const void *b)
{
    struct appopt_affinity_rule *ra = *(struct appopt_affinity_rule **)a;
    struct appopt_affinity_rule *rb = *(struct appopt_affinity_rule **)b;
    return rb->priority - ra->priority;
}

static void appopt_apply_affinity(pid_t tid, const struct cpumask *cpus)
{
    int ret;
    ret = sched_setaffinity(tid, cpus);
    if (ret != 0) {
        pr_err("AppOpt: failed to set affinity for tid %d: %d\n", tid, ret);
    }
}

static void appopt_collect_processes(struct appopt_config *cfg)
{
    struct task_struct *task;
    struct task_struct *t;
    char comm[TASK_COMM_LEN];
    char full_pkg[APPOPT_MAX_PKG_LEN];
    bool matched;
    struct appopt_affinity_rule **thread_rules;
    size_t num_thread_rules;
    size_t thread_rules_cap;
    size_t i;
    struct appopt_affinity_rule *rule;
    struct appopt_affinity_rule **new_thread_rules;
    struct cpumask base_cpus;
    char base_cpuset[128];
    char tcomm[TASK_COMM_LEN];
    struct cpumask cpus;
    int highest_priority;
    size_t best_rule_idx;
    const char *rule_thread;

    for_each_process(task) {
        const char *pkg_to_match;
        
        get_task_comm(comm, task);
        
        // 使用内核API获取完整命令行，避免SELinux权限问题
        full_pkg[0] = '\0';
        if (task->pid > 0) {
            ssize_t ret;
            ret = get_cmdline(task, full_pkg, sizeof(full_pkg) - 1);
            if (ret > 0) {
                full_pkg[ret] = '\0';
                // 替换null字符为空格
                for (i = 0; i < ret; i++) {
                    if (full_pkg[i] == '\0') {
                        full_pkg[i] = ' ';
                    }
                }
                // 移除末尾的空格
                for (i = ret - 1; i > 0; i--) {
                    if (full_pkg[i] == ' ') {
                        full_pkg[i] = '\0';
                    } else {
                        break;
                    }
                }
            }
        }
        
        // 如果无法获取完整包名，使用进程名
        pkg_to_match = full_pkg[0] ? full_pkg : comm;

        matched = false;
        thread_rules = NULL;
        num_thread_rules = 0;
        thread_rules_cap = 0;

        for (i = 0; i < cfg->num_pkgs; i++) {
            const char *pkg_name = cfg->pkgs[i];
            if (strcmp(pkg_name, pkg_to_match) == 0) {
                matched = true;
                break;
            }
        }

        if (!matched) {
            for (i = 0; i < cfg->num_wildcard_rules; i++) {
                rule = cfg->wildcard_rules[i];
                if (appopt_fnmatch(rule->pkg, pkg_to_match) == 0) {
                    matched = true;
                    break;
                }
            }
        }

        if (matched) {
            thread_rules_cap = 8;
            thread_rules = kzalloc(thread_rules_cap * sizeof(*thread_rules), GFP_KERNEL);
            if (thread_rules) {
                for (i = 0; i < cfg->num_rules; i++) {
                    bool pkg_match;
                    rule = &cfg->rules[i];
                    pkg_match = (strcmp(rule->pkg, pkg_to_match) == 0);
                    if (pkg_match || (rule->is_wildcard && appopt_fnmatch(rule->pkg, pkg_to_match) == 0)) {
                        if (num_thread_rules >= thread_rules_cap) {
                            thread_rules_cap *= 2;
                            new_thread_rules = krealloc(thread_rules, thread_rules_cap * sizeof(*thread_rules), GFP_KERNEL);
                            if (!new_thread_rules) {
                                kfree(thread_rules);
                                thread_rules = NULL;
                                break;
                            }
                            thread_rules = new_thread_rules;
                        }
                        thread_rules[num_thread_rules++] = rule;
                    }
                }

                if (num_thread_rules > 1) {
                    sort(thread_rules, num_thread_rules, sizeof(*thread_rules), appopt_compare_rules, NULL);
                }

                cpumask_clear(&base_cpus);
                memset(base_cpuset, 0, sizeof(base_cpuset));

                for (i = 0; i < num_thread_rules; i++) {
                    rule = thread_rules[i];
                    if (!rule->thread[0]) {
                        cpumask_or(&base_cpus, &base_cpus, &rule->cpus);
                        strncpy(base_cpuset, rule->cpuset_dir, sizeof(base_cpuset) - 1);
                        base_cpuset[sizeof(base_cpuset) - 1] = '\0';
                        break;
                    }
                }

                for_each_thread(task, t) {
                    get_task_comm(tcomm, t);

                    cpumask_clear(&cpus);
                    highest_priority = -1;
                    best_rule_idx = 0;

                    for (i = 0; i < num_thread_rules; i++) {
                        rule = thread_rules[i];
                        rule_thread = rule->thread;

                        if (strcmp(rule_thread, tcomm) == 0 || (!rule_thread[0] && (!tcomm[0] || strcmp(tcomm, " ") == 0))) {
                            cpumask_or(&cpus, &cpus, &rule->cpus);
                            break;
                        } else if (rule->priority < 1000 && appopt_fnmatch(rule_thread, tcomm) == 0) {
                            if (rule->priority > highest_priority) {
                                highest_priority = rule->priority;
                                best_rule_idx = i;
                            }
                        }
                    }

                    if (highest_priority >= 0) {
                        cpumask_or(&cpus, &cpus, &thread_rules[best_rule_idx]->cpus);
                    } else {
                        cpumask_or(&cpus, &cpus, &base_cpus);
                    }

                    if (!cpumask_empty(&cpus)) {
                        appopt_apply_affinity(task_pid_nr(t), &cpus);
                    }
                }

                kfree(thread_rules);
            }
        }
    }
}

static int appopt_thread_fn(void *data)
{
    struct appopt_cpu_topology topo;
    int ret;
    struct kstat st;

    ret = appopt_init_cpu_topo(&topo);
    // 不再因为初始化失败而退出，因为appopt_init_cpu_topo现在总是返回成功
    // 即使无法获取CPU信息，也会使用默认值

    while (!kthread_should_stop()) {
        if (vfs_stat(APPOPT_CONFIG_PATH, &st) == 0) {
            if (!appopt_current_config || appopt_current_config->mtime != st.ino) {
                struct appopt_config *new_config = appopt_load_config(APPOPT_CONFIG_PATH, &topo);
                if (new_config) {
                    if (appopt_current_config) {
                        appopt_free_config(appopt_current_config);
                    }
                    appopt_current_config = new_config;
                    pr_info("AppOpt: config updated\n");
                }
            }
        }

        if (appopt_current_config) {
            appopt_collect_processes(appopt_current_config);
        }

        msleep(appopt_interval * 1000);
    }

    if (appopt_current_config) {
        appopt_free_config(appopt_current_config);
        appopt_current_config = NULL;
    }

    return 0;
}

static int appopt_status_show(struct seq_file *m, void *v)
{
    seq_printf(m, "AppOpt Version: %s\n", APPOPT_VERSION);
    seq_printf(m, "Running: %s\n", appopt_running ? "yes" : "no");
    seq_printf(m, "Check Interval: %d seconds\n", appopt_interval);
    seq_printf(m, "Config Path: %s\n", APPOPT_CONFIG_PATH);

    if (appopt_current_config) {
        seq_printf(m, "Loaded Rules: %zu\n", appopt_current_config->num_rules);
        seq_printf(m, "Loaded Packages: %zu\n", appopt_current_config->num_pkgs);
        seq_printf(m, "Wildcard Rules: %zu\n", appopt_current_config->num_wildcard_rules);
    } else {
        seq_printf(m, "Loaded Rules: 0\n");
        seq_printf(m, "Loaded Packages: 0\n");
        seq_printf(m, "Wildcard Rules: 0\n");
    }

    return 0;
}

static int appopt_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, appopt_status_show, NULL);
}

static const struct file_operations appopt_status_fops = {
    .owner = THIS_MODULE,
    .open = appopt_status_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int __init appopt_init(void)
{
    pr_info("AppOpt: initializing version %s\n", APPOPT_VERSION);

    appopt_proc_dir = proc_mkdir("appopt", NULL);
    if (!appopt_proc_dir) {
        pr_err("AppOpt: failed to create proc directory\n");
        return -ENOMEM;
    }

    appopt_status_entry = proc_create("status", 0444, appopt_proc_dir, &appopt_status_fops);
    if (!appopt_status_entry) {
        pr_err("AppOpt: failed to create status entry\n");
        proc_remove(appopt_proc_dir);
        return -ENOMEM;
    }

    appopt_thread = kthread_run(appopt_thread_fn, NULL, "appoptd");
    if (IS_ERR(appopt_thread)) {
        pr_err("AppOpt: failed to create kernel thread: %ld\n", PTR_ERR(appopt_thread));
        proc_remove(appopt_status_entry);
        proc_remove(appopt_proc_dir);
        return -ENOMEM;
    }

    appopt_running = true;
    pr_info("AppOpt: initialized successfully\n");
    return 0;
}

static void __exit appopt_exit(void)
{
    pr_info("AppOpt: exiting\n");

    if (appopt_running) {
        appopt_running = false;
        if (appopt_thread) {
            kthread_stop(appopt_thread);
            appopt_thread = NULL;
        }
    }

    if (appopt_status_entry) {
        proc_remove(appopt_status_entry);
        appopt_status_entry = NULL;
    }

    if (appopt_proc_dir) {
        proc_remove(appopt_proc_dir);
        appopt_proc_dir = NULL;
    }

    pr_info("AppOpt: exited successfully\n");
}

module_init(appopt_init);
module_exit(appopt_exit);

module_param(appopt_interval, int, 0644);
MODULE_PARM_DESC(appopt_interval, "Check interval in seconds (default: 2)");
