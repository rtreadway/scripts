# Tools to aid in viewing data
from pprint import PrettyPrinter

class VerticalDictPrettyPrinter(PrettyPrinter):
    '''Custom pretty printer for printing dictionaries vertically\n
     in order to best observe k/v pairs'''
    def format(self, object, context, maxlevels, level):
        if isinstance(object, dict):
            items = [(k, object[k]) for k in sorted(object.keys())]
            reprs = ["{\n"]
            for k, v in items:
                krepr, kreadable, krecur = super().format(k, context, maxlevels, level)
                vrepr, vreadable, vrecur = super().format(v, context, maxlevels, level + 1)
                reprs.append(self._indent_per_level * (level + 1) * ' ' + f"{krepr}: {vrepr},\n")
            reprs.append(self._indent_per_level * level * ' ' + "}")
            return ''.join(reprs), True, False
        else:
            return super().format(object, context, maxlevels, level)
