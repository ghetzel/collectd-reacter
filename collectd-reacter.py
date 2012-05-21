#===============================================================================
# collectd-reacter - a flexible threshold detection and response plugin
#
#  SOURCE
#        https://github.com/ghetzel/collectd-reacter
#
#  AUTHOR
#        Gary Hetzel <garyhetzel@gmail.com>
#===============================================================================
import collectd
import yaml
import sys
import os
import re
import subprocess

threshold_file = None
report_stats   = True
config         = None
checkstack     = {}

CMP_OKAY=0
CMP_WARN=1
CMP_FAIL=2
ACTIONS = ['exec']
PLUGIN_NAME='reacter'


# -----------------------------------------------------------------------------
# CALLBACK: config()
#   processes the collectd.conf configuration stanza for this plugin
#
def config(c):
  global threshold_file, config, report_stats

  for ci in c.children:
    if ci.key == 'ThresholdFile':
      threshold_file = ci.values[0]
    elif ci.key == 'ReportStats':
      report_stats = ci.values[0]
   
  if not threshold_file:
    raise Exception('Must specify a ThresholdFile configuration file (yaml)')

  config = yaml.safe_load(open(threshold_file, 'r'))


# -----------------------------------------------------------------------------
# CALLBACK: read()
#   this is what collectd calls to read values from the plugin
#
def read(data=None):
  return
  # global report_stats, checkstack

  # if report_stats:  
  #   for host in checkstack:
  #     for metric in checkstack[host]:
  #       if checkstack[host][metric]['rule'].get('report') == True:
  #         name = (checkstack[host][metric]['rule'].get('name') or metric)

  #       # dispatch warning stats
  #         create_value(name, 'threshold_warn',
  #           [ checkstack[host][metric]['stats']['warn-min'], checkstack[host][metric]['stats']['warn-max'] ]).dispatch()

  #       # dispatch failure stats
  #         create_value(name, 'threshold_fail',
  #           [ checkstack[host][metric]['stats']['fail-min'], checkstack[host][metric]['stats']['fail-max'] ]).dispatch()

  #       # dispatch success stats
  #         create_value(name, 'threshold_success',
  #           [ checkstack[host][metric]['stats']['success'] ]).dispatch()

  #         create_value(name, 'hits',
  #           [ checkstack[host][metric]['last_breach_count'] ]).dispatch()

  #         create_value(name, 'status',
  #           [ checkstack[host][metric]['last_status'] ]).dispatch()


# -----------------------------------------------------------------------------
# create_value
#   create and return a new collectd.Value() object
#
def create_value(name, type_name, values):
  vl = collectd.Values(plugin=PLUGIN_NAME, type=type_name)
  vl.plugin_instance = name
  vl.values = values

  return vl


# -----------------------------------------------------------------------------
# CALLBACK: collectd write()
#   this is what collectd calls when it receives a new metric observation
#
def write(vl, data=None):
  global config, report_stats
  hosts = config['thresholds']['hosts']
  rules = {}

  for host in hosts.keys():
    if hosts[host]:
      if host == 'default' or re.match(host, vl.host):
        for rule in hosts[host].keys():
          rules[rule] = hosts[host][rule]

  for rule in rules.keys():
    plugin = vl.plugin +  ('-'+vl.plugin_instance if len(vl.plugin_instance) > 0 else '')
    type = vl.type +  ('-'+vl.type_instance if len(vl.type_instance) > 0 else '')
    metric = plugin + ('.'+type if len(type) > 0 else '')

    for i in vl.values:
      if re.match(rule, metric):
        #print 'PUSH', metric, i
        push_metric(vl, metric, i, rules[rule])


# -----------------------------------------------------------------------------
# check_value
#   performs the threshold checks for a given value and returns a status code
#
#   returns:
#     -2  exceeded failure minimum
#     -1  exceeded warning minimum
#      0  success
#      1  exceeded warning maxmimum
#      2  exceeded failure maxmimum
#
def check_value(value, threshold):
  checks = [
    ('fail', 'min', (-1 * CMP_FAIL)),
    ('fail', 'max', CMP_FAIL),
    ('warn', 'min', (-1 * CMP_WARN)),
    ('warn', 'max', CMP_WARN)
  ]

# perform actual threshold checks
  for i in checks:
    try:
      if i[2] < 0 and value < threshold[i[0]][i[1]]:
        return i[2], threshold[i[0]]
      elif i[2] > 0 and value > threshold[i[0]][i[1]]:
        return i[2], threshold[i[0]]
    except KeyError:
      continue

  return 0, threshold.get('okay')



# -----------------------------------------------------------------------------
# init_check_stack
#   initializes the checkstack data structure, used to persist a short-term
#   record of execution and maintain state
#
def init_check_stack(vlist, metric):
  global checkstack, report_stats
  host = vlist.host

# initialize host dict if not already there
  if not host in checkstack:
    checkstack[host] = {}

# initialize metric dict in host if not already there
  if not metric in checkstack[host]:
    checkstack[host][metric] = {
      'raw': vlist,
      'host': host,
      'metric': metric,
      'rule': None,
      'observations': [],
      'last_status': 0,
      'last_condition': 'okay',
      'last_breach_count': 0,
      'last_violation_state': False,
      'violation': False,      
      'stats': {
        'fail-min': 0,
        'fail-max': 0,
        'warn-min': 0,
        'warn-max': 0,
        'breaches': 0,
        'success':  0,
        'checks':   0
      }
    }


# -----------------------------------------------------------------------------
# push_metric
#   pushes a new metric observation onto a host/metric-keyed stack (checkstack)
#   also performs the value check (calls check_value) and stores the status code
#   finally, determines whether this observation is in violation based on the
#   threshold configuration
#
#   returns:
#     the observation record as stored in checkstack (for convenience)
#
def push_metric(vlist, metric, value, rule):
  global checkstack
  init_check_stack(vlist, metric)
  host = vlist.host
  hits = rule.get('hits') or 1
  observations = rule.get('observations') or hits

# save the current rule
  if not checkstack[host][metric]['rule']:
    checkstack[host][metric]['rule'] = rule

# push observation
  checkstack[host][metric]['observations'].append(value)

# store the previous n observations
  if len(checkstack[host][metric]['observations']) > observations:
    checkstack[host][metric]['observations'].pop(0)

# do value check
  res, cond = check_value(value, rule)

  checkstack[host][metric]['last_status'] = res
  checkstack[host][metric]['last_condition'] = cond

# set last violation state
  checkstack[host][metric]['last_violation_state'] = checkstack[host][metric]['violation']

# increment checks
  checkstack[host][metric]['stats']['checks'] += 1

# determine current violation state
  if res == 0:
    checkstack[host][metric]['stats']['success'] += 1

  # only succeed after n passing checks
    if checkstack[host][metric]['stats']['checks'] >= hits:
      checkstack[host][metric]['stats']['checks'] = 0
      checkstack[host][metric]['violation'] = False
      perform_action(checkstack[host][metric])

  else:
  # only violate every n breaches
    if checkstack[host][metric]['stats']['checks'] >= hits:
      checkstack[host][metric]['stats']['checks'] = 0
      checkstack[host][metric]['violation'] = True
      perform_action(checkstack[host][metric])

  return checkstack[host][metric]


# -----------------------------------------------------------------------------
# perform_action
#   determines what action to perform (if any) based on an observation
#
def perform_action(observe):
  rule = observe.get('rule')

  if rule:
    for k in ACTIONS:
      try:
        func = globals()['perform_action_'+k]
        cond = observe['last_condition']

        if cond and cond.get(k):
        # if in violation...
          if observe['violation']:
          # ...and either persist=true OR the last observation was clean
            if not observe['last_violation_state'] or observe['rule'].get('persist'):
              print 'VIOLATE ', observe['metric']
              func(observe, cond)

        # else, not in violation...
          else:
          # ...and persist_ok=true OR this is the first clear observation
            if observe['last_violation_state'] or observe['rule'].get('persist_ok'):
              print 'OKAY ', observe['metric']
              func(observe, cond)

      except KeyError:
        pass

# -----------------------------------------------------------------------------
# perform_action_exec
#   executes a shell script (called by perform_action)
#
def perform_action_exec(observe, condition):
  global config

# setup environment
  env = os.environ.copy()
  env["COLLECTD_HOST"] = str(observe['host'])
  env["COLLECTD_PLUGIN"] = str(observe['raw'].plugin)
  env["COLLECTD_PLUGIN_INSTANCE"] = str(observe['raw'].plugin_instance)
  env["COLLECTD_TYPE"] = str(observe['raw'].type)
  env["COLLECTD_TYPE_INSTANCE"] = str(observe['raw'].type_instance)
  env["COLLECTD_METRIC"] = str(observe['metric'])
  env["COLLECTD_THRESHOLD_STATE"] = str(observe['last_status'])
  env["COLLECTD_VALUE"] = str(observe['observations'][-1])

# export global generic params as envvars
  if config['thresholds'].get('params'):
    for k in config['thresholds']['params']:
      env['COLLECTD_PARAM_'+k.upper()] = str(config['thresholds']['params'][k])

# override/augment them with params from lower levels
  if condition.get('params'):
    for k in condition['params']:
      env['COLLECTD_PARAM_'+k.upper()] = str(condition['params'][k])


# execute
  subprocess.Popen(condition['exec'], env=env, shell=True, stdin=None, stdout=None, stderr=None)


# -----------------------------------------------------------------------------
# perform_action_notify
#   dispatches a collectd notification back to the daemon
#   useful for any plugins that respond to these notifications
#
def perform_action_notify(observe, condition):
  return

# -----------------------------------------------------------------------------
# shutdown
#   called once on daemon shutdown
#
def shutdown():
  print "Stopping collectd-reacter"


# -----------------------------------------------------------------------------
# Register Callbacks
# -----------------------------------------------------------------------------
#collectd.register_init(init)
collectd.register_config(config)
collectd.register_read(read)
collectd.register_write(write)
collectd.register_shutdown(shutdown)
