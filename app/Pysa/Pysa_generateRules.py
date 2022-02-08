from app.config import Pyre_Config

""" 
LIMITATION: OpenTracing cuts of tag-data if it reaches a certain length.
Individual identification of taint flows based on tainted data is 
not possible when a string is too long, this is why only a differentiation 
between implicit and exact sources and sinks is made.
"""

# Receives a span (list of tags) and an attack argument
# Extracts sources and sinks from tags whenever the attack payload is discovered within a data-object
def extractSourcesSinks(lisTags, attack):

    print('--- Generating Pysa security rules according to filtered set of tags ---')

    # Instantiate lists to collect potential source operations

    # Exact sources are operations that retrieve the exact value of the attack argument
    lis_sources_exact = []
    # Implicit sources are operations that retrieve a data-value that contains the attack argument
    lis_sources_implicit = []
    # Instantiate lists for exact and implicit sink operations and arguments
    # Exact sink operations are operations that receive the exact value of the attack argument
    lis_sink_operations_exact = []
    # Exact sink arguments are the arguments that hold the exact value of the attack argument
    lis_sink_arguments_exact = []
    # Implicit sink operations are operations that receive a data-value that contains the attack argument
    lis_sink_operations_implicit = []
    # Implicit sink arguments are the arguments that hold contain the attack argument
    lis_sink_arguments_implicit = []

    # Analyze all tags from a list of tags
    for tag in lisTags:

        # Separate data values from possible sink argument names that are left of the :: delimiter
        # Receive only the data value
        if "::" in str(tag["value"]):
            data = str(tag["value"]).split('::')[1]
        else:
            data = str(tag["value"])

        # If the data value corresponds exactly to the attack payload:
        if data == str(attack):
            # If the operation is a source operation, store it in the list of possible exact sources
            if "OUT::" in tag["key"]:
                # Separate the operation from the OUT:: tag
                possible_source_operation = tag["key"].split('::')[1]
                lis_sources_exact.append(possible_source_operation)
                continue
            # If the operation is a sink operation, store it in the list of possible exact sinks
            if "IN::" in tag["key"]:
                # Separate the operation from the IN:: tag
                possible_sink_operation = tag["key"].split('::')[1]
                lis_sink_operations_exact.append(possible_sink_operation)
                # Separate the argument from the argument name, left of the :: delimiter
                possible_sink_argument = tag["value"].split('::')[0]
                lis_sink_arguments_exact.append(possible_sink_argument)
                continue

        """
        If the identification of taint flows based on tainted data was possible:
        At this point the function would loop through lisTags and detect every implicitly tainted data value. 
        Afterwards, the start-point and end-point of the taint flow of every tainted data value is collected and
        declared as source/ sink. 
        """

        # If the data value does not correspond exactly to the attack payload but contains it:
        if attack in data and data != attack:
            # If the operation is a source operation, store it in the list of possible implicit sources
            if "OUT::" in tag["key"]:
                # Separate the operation from the OUT:: tag
                possible_source_operation = tag["key"].split('::')[1]
                lis_sources_implicit.append(possible_source_operation)
                continue
            # If the operation is a sink operation, store it in the list of possible implicit sinks
            if "IN::" in tag["key"]:
                # Separate the operation from the IN:: tag
                possible_sink_operation = tag["key"].split('::')[1]
                lis_sink_operations_implicit.append(possible_sink_operation)
                # Separate the argument from the argument name, left of the :: delimiter
                possible_sink_argument = tag["value"].split('::')[0]
                lis_sink_arguments_implicit.append(possible_sink_argument)
                continue

    # If exact sources were found
    if len(lis_sources_exact) > 0:
        # Get the first source of the list
        # (first operation an attack payload was ever retrieved from within a span)
        # Write the source to a .pysa file
        writeSource(lis_sources_exact[0],
                    Pyre_Config.XSS_SOURCE_RULE)
    # If exact sinks were found
    if len(lis_sink_operations_exact) > 0:
        # Get the last sink of the list
        # (last operation an attack payload was ever passed to within a span)
        # Write the sink to a .pysa file
        writeSink(lis_sink_operations_exact[-1],
                  lis_sink_arguments_exact[-1],
                  Pyre_Config.XSS_SINK_RULE)

    # If implicit sources were found
    if len(lis_sources_implicit) > 0:
        # Get the first source of the list
        # (first operation an attack payload was ever retrieved from within a span)
        # Write the source to a .pysa file
        writeSource(lis_sources_implicit[0],
                    Pyre_Config.XSS_SOURCE_RULE)
    # If implicit sinks were found
    if len(lis_sink_operations_implicit) > 0:
        # Get the last sink of the list
        # (last operation an attack payload was ever passed to within a span)
        # Write the sink to a .pysa file
        writeSink(lis_sink_operations_implicit[-1],
                  lis_sink_arguments_implicit[-1],
                  Pyre_Config.XSS_SINK_RULE)

# Receives a source and a rule ( -> UserControlled)
# Writes a source rule that is interpretable by Pysa
def writeSource(source, rule):
    print('Source ' + '"' + source + '"' + ' is written to: ' + Pyre_Config.PYSA_FILE_DIR)
    with open(Pyre_Config.PYSA_FILE_DIR, 'a') as pysa_file:
        if 'def' in source:
            pysa_file.write('\n' + source + ' -> ' + rule + ': ...')
        else:
            pysa_file.write('\n' + source + ': ' + rule + ' = ...')

# Receives a sink operation, a sink argument and a rule ( -> XSS)
# Writes a sink rule that is interpretable by Pysa
def writeSink(sink_op, sink_arg, rule):
    print('Sink ' +'"' + sink_op + '"'+ ' is written to: ' + Pyre_Config.PYSA_FILE_DIR)
    # this is a dirty-fix: def db.add_comment(comment), rule is added
    # at add_comment AND (comment)
    # result -> def db.add_comment: TaintSink[XSS](comment: TaintSink[XSS]): ...
    # FIX : get the substring after brackets
    arg_substring = sink_op.split('(')[1]
    op_substring = sink_op.split('(')[0]
    with open(Pyre_Config.PYSA_FILE_DIR, 'a') as pysa_file:
        pysa_file.write('\n' + op_substring + '(' +
                        arg_substring.replace(sink_arg,
                        (sink_arg + ': ' + rule)) + ': ...')

# Reads the newly generated .pysa file, appends all security rules to a list and returns it
def readResults():
    with open(Pyre_Config.PYSA_FILE_DIR) as results:
        lines = results.readlines()
        lines = [line.rstrip() for line in lines]
        return lines

