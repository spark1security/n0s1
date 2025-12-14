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
    from . import local_filesystem_controller as local_filesystem_controller
    from . import asana_controller as asana_controller
    from . import zendesk_controller as zendesk_controller
    from . import github_controller as github_controller
    from . import gitlab_controller as gitlab_controller
    from . import wrike_controller as wrike_controller
    from . import slack_controller as slack_controller
except Exception:
    import n0s1.controllers.jira_controller as jira_controller
    import n0s1.controllers.confluence_controller as confluence_controller
    import n0s1.controllers.linear_controller as linear_controller
    import n0s1.local_filesystem_controller as local_filesystem_controller
    import n0s1.controllers.asana_controller as asana_controller
    import n0s1.controllers.zendesk_controller as zendesk_controller
    import n0s1.controllers.github_controller as github_controller
    import n0s1.controllers.gitlab_controller as gitlab_controller
    import n0s1.controllers.wrike_controller as wrike_controller
    import n0s1.controllers.slack_controller as slack_controller

factory.register_platform("", jira_controller.JiraController)
factory.register_platform("jira", jira_controller.JiraController)
factory.register_platform("jira_scan", jira_controller.JiraController)
factory.register_platform("confluence", confluence_controller.ConfluenceController)
factory.register_platform("confluence_scan", confluence_controller.ConfluenceController)
factory.register_platform("linear", linear_controller.LinearController)
factory.register_platform("linear_scan", linear_controller.LinearController)
factory.register_platform("local", local_filesystem_controller.LocalController)
factory.register_platform("local_scan", local_filesystem_controller.LocalController)
factory.register_platform("asana", asana_controller.AsanaController)
factory.register_platform("asana_scan", asana_controller.AsanaController)
factory.register_platform("zendesk", zendesk_controller.ZendeskController)
factory.register_platform("zendesk_scan", zendesk_controller.ZendeskController)
factory.register_platform("github", github_controller.GitHubController)
factory.register_platform("github_scan", github_controller.GitHubController)
factory.register_platform("gitlab", gitlab_controller.GitLabController)
factory.register_platform("gitlab_scan", gitlab_controller.GitLabController)
factory.register_platform("wrike", wrike_controller.WrikeController)
factory.register_platform("wrike_scan", wrike_controller.WrikeController)
factory.register_platform("slack", slack_controller.SlackController)
factory.register_platform("slack_scan", slack_controller.SlackController)
