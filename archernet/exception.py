
import sys

_cause_message = (
    "\nThe above exception was the direct cause "
    "of the following exception:\n\n")

_context_message = (
    "\nDuring handling of the above exception, "
    "another exception occurred:\n\n")

def format_exception(exc: Exception):
    output = []
    while exc:
        if exc.__cause__ is not None:
            chained_msg = _cause_message
            chained_exc = exc.__cause__
        elif (exc.__context__  is not None and
                not exc.__suppress_context__):
            chained_msg = _context_message
            chained_exc = exc.__context__
        else:
            chained_msg = exc
            chained_exc = None

        output.append((chained_msg, exc))
        exc = chained_exc

    for msg, exc in output:
        if msg is not None:
            print(msg, file=sys.stderr)
        if hasattr(exc, 'stack'):
            print('Traceback:\n', file=sys.stderr)
            print(exc.stack.format(), file=sys.stderr)
        
        if hasattr(exc, 'format_exception_only'):
            print(exc.format_exception_only(), file=sys.stderr)
