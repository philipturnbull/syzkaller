package prog

import (
)

type ResearchConfig struct {
	requireAllThreadCallsToUseResultArg bool
	requireResourceOverlap bool
	forceParentThread []string
	requiredResource []string
	requiredCalls []string
	expectedSeedFiles []string
	doNotMinimizePointersToGroup []string
}

func currentResearchConfig() ResearchConfig {
	return ResearchConfig{
		requireAllThreadCallsToUseResultArg: false,
		requireResourceOverlap: false,
		forceParentThread: []string {
			"pipe2$watch_queue",
		},
		requiredResource: []string {
			"fd_watch_queue",
		},
		requiredCalls: []string {
			"pipe2$watch_queue",
			"ioctl$IOC_WATCH_QUEUE_SET_SIZE",
			"keyctl$KEYCTL_WATCH_KEY",
		},
		expectedSeedFiles: []string {
			"add_key_keyring",
			"key_notification",
			"key_notification_filter",
			"keyctl_clear",
			"keyctl_link",
			"keyctl_revoke",
			"keyctl_update",
		},
		doNotMinimizePointersToGroup: []string {
			"pipefd$watch_queue",
		},
	}
}

func ExpectedSeedFiles() []string {
	return currentResearchConfig().expectedSeedFiles
}

func requireAllThreadCallsToUseResultArg() bool {
	return currentResearchConfig().requireAllThreadCallsToUseResultArg
}

func requireResourceOverlap() bool {
	return currentResearchConfig().requireResourceOverlap
}

func forceParentThread(meta *Syscall) bool {
	names := currentResearchConfig().forceParentThread

	for _, name := range names {
		if meta.Name == name {
			return true
		}
	}

	return false
}

func requiredResource(a *ResourceType) bool {
	names := currentResearchConfig().requiredResource

	for _, name := range names {
		if a.TypeName == name {
			return true
		}
	}

	return false
}

func requiredCalls() []string {
	return currentResearchConfig().requiredCalls
}

func doNotMinimizePointersToGroup(group *GroupArg) bool {
	names := currentResearchConfig().doNotMinimizePointersToGroup

	for _, name := range names {
		if group.Type().Name() == name {
			return true
		}
	}

	return false
}
