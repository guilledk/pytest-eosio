#!/usr/bin/env python3

def collect_stdout(out):
    output = ''
    for action_trace in out['processed']['action_traces']:
        if 'console' in action_trace:
            output += action_trace['console']

    return output