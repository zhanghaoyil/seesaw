
class BaseStruct(object):
    fields = ()

    def _fill_struct(self, data):
        for k,v in zip(self.fields, data):
            setattr(self, k, v)


class DictWrapper(dict):
    def __getattr__(self, attr):
        return self[attr]
