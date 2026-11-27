import { reactive, ref, computed, watch } from 'vue'
import { defineStore } from 'pinia'
import i18n from '@/i18n'
import { useAuthStore } from '@/stores/auth'
import { useDeploymentCapabilitiesStore } from '@/stores/deploymentCapabilities'
import type { DeploymentCapabilityKey } from '@/config/deploymentCapabilities'
import type { QuestionOrigin } from '@/utils/questionOrigin'

type MenuChild = Record<string, any>

interface MenuItem {
  title: string
  titleKey?: string
  icon: string
  path: string
  childrenPath?: string
  children?: MenuChild[]
  requiredCapability?: DeploymentCapabilityKey
}

const createMenuChildren = () => reactive<MenuChild[]>([])

export const useMenuStore = defineStore('menuStore', () => {
  const menuArr = reactive<MenuItem[]>([
    {
      title: '',
      titleKey: 'menu.newChat',
      icon: 'prefixIcon',
      path: 'creatChat',
      childrenPath: 'chat',
      children: createMenuChildren()
    },
    { title: '', titleKey: 'menu.knowledgeBase', icon: 'zhishiku', path: 'knowledge-bases' },
    // Artifacts only exist where skills run in a sandbox.
    { title: '', titleKey: 'menu.artifacts', icon: 'artifact', path: 'artifacts', requiredCapability: 'settings.sandbox' },
    { title: '', titleKey: 'menu.agents', icon: 'agent', path: 'agents', requiredCapability: 'agents' },
    { title: '', titleKey: 'menu.automations', icon: 'automation', path: 'automations' },
    { title: '', titleKey: 'toolbox.title', icon: 'toolbox', path: 'toolbox' },
    { title: '', titleKey: 'menu.organizations', icon: 'organization', path: 'organizations', requiredCapability: 'organizations' },
    { title: '', titleKey: 'menu.settings', icon: 'setting', path: 'settings' },
    { title: '', titleKey: 'menu.logout', icon: 'logout', path: 'logout' }
  ])

  const isFirstSession = ref(false)
  const firstQuery = ref('')
  const firstMentionedItems = ref<any[]>([])
  const firstModelId = ref('')
  const firstImageFiles = ref<any[]>([])
  const firstAttachmentFiles = ref<any[]>([])
  const firstQuestionOrigin = ref<QuestionOrigin | null>(null)
  const prefillQuery = ref('')

  const applyMenuTranslations = () => {
    menuArr.forEach(item => {
      if (item.titleKey) {
        item.title = i18n.global.t(item.titleKey)
      }
    })
  }

  applyMenuTranslations()

  watch(
    () => [
      i18n.global.locale.value,
      i18n.global.messages?.value?.[
        i18n.global.locale.value as keyof typeof i18n.global.messages.value
      ],
    ],
    () => {
      applyMenuTranslations()
    },
  )

  const liteHiddenPaths = new Set(['logout', 'organizations'])

  // 共享空间 (organizations) 仅对当前空间的 admin / owner 暴露入口。
  // viewer / contributor 即便在共享空间里拥有资源，也无需自行管理共享关系，
  // 入口在侧栏只会徒增噪音；后端 RBAC 才是权限的最终来源（见 middleware/rbac.go）。
  //
  // 查看者 (viewer) 只保留提问能力：侧栏仅剩「新对话」和历史会话列表。
  //
  // 这是一套名单制、以问答为中心的使用方式——查看者在企业里就是来提问的。
  // 「知识库 / 智能体 / 产物」是只读浏览面（后端 RBAC 已禁止其创建与上传），
  // 「自动化 / 工具箱 / 用户中心 / 设置」则与其职责无关，一律隐藏。
  // 注意这只是导航层收敛：直接访问路由仍由后端 RBAC 拦截，权限判定不变。
  const VIEWER_ALLOWED_PATHS = new Set(['creatChat'])

  const visibleMenuArr = computed(() => {
    const authStore = useAuthStore()
    const deploymentCapabilities = useDeploymentCapabilitiesStore()
    const isViewer = authStore.currentTenantRole === 'viewer'
    return menuArr.filter(item => {
      if (authStore.isLiteMode && liteHiddenPaths.has(item.path)) {
        return false
      }
      // logout is the only non-sidebar entry kept: the account dropdown still
      // needs a way out (UserMenu renders it separately from menuArr).
      if (isViewer && !VIEWER_ALLOWED_PATHS.has(item.path) && item.path !== 'logout') {
        return false
      }
      if (item.path === 'organizations' && !authStore.hasRole('admin')) {
        return false
      }
      if (!deploymentCapabilities.isSupported(item.requiredCapability)) {
        return false
      }
      return true
    })
  })

  const chatMenuIndex = menuArr.findIndex(item => item.path === 'creatChat')

  const clearMenuArr = () => {
    const chatMenu = menuArr[chatMenuIndex]
    if (chatMenu && chatMenu.children) {
      chatMenu.children = createMenuChildren()
    }
  }

  const updatemenuArr = (obj: any) => {
    const chatMenu = menuArr[chatMenuIndex]
    if (!chatMenu.children) {
      chatMenu.children = createMenuChildren()
    }
    const exists = chatMenu.children.some((item: MenuChild) => item.id === obj.id)
    if (!exists) {
      chatMenu.children.push(obj)
    }
  }

  const updataMenuChildren = (item: MenuChild) => {
    const chatMenu = menuArr[chatMenuIndex]
    if (!chatMenu.children) {
      chatMenu.children = createMenuChildren()
    }
    chatMenu.children.unshift(item)
  }

  const updatasessionTitle = (sessionId: string, title: string) => {
    const chatMenu = menuArr[chatMenuIndex]
    chatMenu.children?.forEach((item: MenuChild) => {
      if (item.id === sessionId) {
        item.title = title
        item.isNoTitle = false
      }
    })
  }

  const changeIsFirstSession = (payload: boolean) => {
    isFirstSession.value = payload
  }

  const changeFirstQuery = (payload: string, mentionedItems: any[] = [], modelId: string = '', imageFiles: any[] = [], attachmentFiles: any[] = [], questionOrigin: QuestionOrigin | null = null) => {
    firstQuery.value = payload
    firstMentionedItems.value = mentionedItems
    firstModelId.value = modelId
    firstImageFiles.value = imageFiles
    firstAttachmentFiles.value = attachmentFiles
    firstQuestionOrigin.value = questionOrigin
  }

  const setPrefillQuery = (q: string) => {
    prefillQuery.value = q
  }

  const consumePrefillQuery = () => {
    const q = prefillQuery.value
    prefillQuery.value = ''
    return q
  }

  return {
    menuArr,
    visibleMenuArr,
    isFirstSession,
    firstQuery,
    firstMentionedItems,
    firstModelId,
    firstImageFiles,
    firstAttachmentFiles,
    firstQuestionOrigin,
    prefillQuery,
    clearMenuArr,
    updatemenuArr,
    updataMenuChildren,
    updatasessionTitle,
    changeIsFirstSession,
    changeFirstQuery,
    setPrefillQuery,
    consumePrefillQuery
  }
})
