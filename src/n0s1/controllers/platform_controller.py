
class PlatformHollow:
    def __init__(self):
        self.client = None

    def set_config(self, config):
        return self.is_connected()

    def get_name(self):
        return "Hollow"

    def is_connected(self):
        return False

    def get_data(self, include_coments=False):
        return None, None, None, None, None

    def post_comment(self, issue, comment):
        return self.is_connected()


class PlatformFactory:
    def __init__(self):
        self._creators = {}

    def register_platform(self, platform, creator):
        self._creators[platform] = creator

    def get_platform(self, platform):
        creator = self._creators.get(platform)
        if creator:
            return creator()
        return PlatformHollow()


global factory
factory = PlatformFactory()

try:
    from . import jira_controller as jira_controller
    from . import confluence_controller as confluence_controller
    from . import linear_controller as linear_controller
except:
    import n0s1.controllers.jira_controller as jira_controller
    import n0s1.controllers.confluence_controller as confluence_controller
    import n0s1.controllers.linear_controller as linear_controller

factory.register_platform("", jira_controller.JiraControler)
factory.register_platform("jira", jira_controller.JiraControler)
factory.register_platform("jira_scan", jira_controller.JiraControler)
factory.register_platform("confluence", confluence_controller.ConfluenceControler)
factory.register_platform("confluence_scan", confluence_controller.ConfluenceControler)
factory.register_platform("linear", linear_controller.LinearControler)
factory.register_platform("linear_scan", linear_controller.LinearControler)
