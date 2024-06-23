try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class PlatformFactory:
    def __init__(self):
        self._creators = {}

    def register_platform(self, platform, creator):
        self._creators[platform] = creator

    def get_platform(self, platform):
        if creator := self._creators.get(platform):
            return creator()
        return hollow_controller.HollowController()


global factory
factory = PlatformFactory()

try:
    from . import jira_controller as jira_controller
    from . import confluence_controller as confluence_controller
    from . import linear_controller as linear_controller
    from . import asana_controller as asana_controller
    from . import wrike_controller as wrike_controller
except Exception:
    import n0s1.controllers.jira_controller as jira_controller
    import n0s1.controllers.confluence_controller as confluence_controller
    import n0s1.controllers.linear_controller as linear_controller
    import n0s1.controllers.asana_controller as asana_controller
    import n0s1.controllers.wrike_controller as wrike_controller

factory.register_platform("", jira_controller.JiraControler)
factory.register_platform("jira", jira_controller.JiraControler)
factory.register_platform("jira_scan", jira_controller.JiraControler)
factory.register_platform("confluence", confluence_controller.ConfluenceControler)
factory.register_platform("confluence_scan", confluence_controller.ConfluenceControler)
factory.register_platform("linear", linear_controller.LinearControler)
factory.register_platform("linear_scan", linear_controller.LinearControler)
factory.register_platform("asana", asana_controller.AsanaControler)
factory.register_platform("asana_scan", asana_controller.AsanaControler)
factory.register_platform("wrike", wrike_controller.WrikeControler)
factory.register_platform("wrike_scan", wrike_controller.WrikeControler)
