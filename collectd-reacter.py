import collectd
import yaml
import sys
import os
import re
import subprocess

threshold_file = None
store_alerts   = True
config         = None
checkstack     = {}
statsstack     = {}

CMP_OKAY=0
CMP_WARN=1
CMP_FAIL=2
ACTIONS = ['exec']

def config(c):
  global threshold_file, config, store_alerts

  for ci in c.children:
    if ci.key == 'ThresholdFile':
      threshold_file = ci.values[0]
    elif ci.key == 'ReportStats':
      store_alerts = ci.values[0]
   
  if not threshold_file:
    raise Exception('Must specify a ThresholdFile configuration file (yaml)')

  config = yaml.safe_load(open(threshold_file, 'r'))


def read(data=None):
  return
#  vl = collectd.Values(type='gauge')


def write(vl, data=None):
  global config, store_alerts
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
        observe = push_metric(vl, metric, i, rules[rule])
     
        perform_action(observe)


def check_value(value, threshold):
  checks = [
    ('fail', 'min', (-1 * CMP_FAIL)),
    ('fail', 'max', CMP_FAIL),
    ('warn', 'min', (-1 * CMP_WARN)),
    ('warn', 'max', CMP_WARN)
  ]

  for i in checks:
    try:
      if i[2] < 0 and value < threshold[i[0]][i[1]]:
        return i[2], threshold[i[0]]
      elif i[2] > 0 and value > threshold[i[0]][i[1]]:
        return i[2], threshold[i[0]]
    except KeyError:
      continue

  return 0, {}


def init_check_stack(vlist, metric):
  global checkstack, statsstack, store_alerts
  host = vlist.host

  if not host in checkstack:
    checkstack[host] = {}

  if not metric in checkstack[host]:
    checkstack[host][metric] = {
      'raw': vlist,
      'host': host,
      'metric': metric,
      'rule': None,
      'observations': [],
      'breaches': 0,
      'last_status': 0,
      'last_condition': 'okay',
      'violation': False
    }

  if store_alerts:
    if not host in statsstack:
      statsstack[host] = {}

    if not metric in statsstack[host]:
      statsstack[host][metric] = {
        'fail-min': 0,
        'fail-max': 0,
        'warn-min': 0,
        'warn-max': 0,
        'okay':     0
      }


def push_metric(vlist, metric, value, rule):
  global checkstack
  init_check_stack(vlist, metric)

  host = vlist.host
  hits = rule.get('hits') or 1
  observations = rule.get('observations') or hits

# actually store things
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

# calculate hits
  if res == 0:
    checkstack[host][metric]['breaches'] = 0
    checkstack[host][metric]['violation'] = False
  else:
    checkstack[host][metric]['breaches'] += 1

# push result stats
  if store_alerts:
    push_stats(host, metric, res)


# check for threshold violation
  if checkstack[host][metric]['breaches'] >= hits:
    checkstack[host][metric]['breaches'] = 0
    checkstack[host][metric]['violation'] = True

  return checkstack[host][metric]


def push_stats(host, metric, status):
  global statsstack

  s = statsstack[host][metric]

  if status == 0:
    s['okay'] += 0
    return

  if abs(status) == 1:
    i = 'warn'
  elif abs(status) == 2:
    i = 'fail'

  if status < 0:
    j = 'min'
  else:
    j = 'max'

  s[i+'-'+j] += 1

  #print statsstack


def perform_action(observe):
  rule = observe.get('rule')

  if rule:
    for k in ACTIONS:
      try:
        func = globals()['perform_action_'+k]
        cond = observe['last_condition']

        if cond and cond.get(k):
          if observe['violation']:
            func(observe, cond)
          else:
            if 'okay' in rule:
              func(observe, cond)

      except KeyError:
        pass
        

def perform_action_exec(observe, condition):
  global config

# setup environment
  env = os.environ.copy()
  env["COLLECTD_HOST"] = str(observe['host'])
  env["COLLECTD_PLUGIN"] = str(observe['raw'].plugin)
  env["COLLECTD_PLUGIN_INSTANCE"] = str(observe['raw'].plugin_instance)
  env["COLLECTD_TYPE"] = str(observe['raw'].type)
  env["COLLECTD_TYPE_INSTANCE"] = str(observe['raw'].type_instance)
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
  subprocess.Popen(condition['exec'], env=env)


def perform_action_notify(observe, condition):
  return

def shutdown():
  print "Stopping collectd-reacter"


# Register Callbacks  
#collectd.register_init(init)
collectd.register_config(config)
collectd.register_read(read)
collectd.register_write(write)
collectd.register_shutdown(shutdown)
