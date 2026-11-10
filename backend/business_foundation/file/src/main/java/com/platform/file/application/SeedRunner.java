package com.platform.file.application;

import com.platform.file.application.command.StorageProviderCommand;
import com.platform.file.config.AppProperties;
import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.repository.StorageProviderRepository;
import com.platform.file.domain.storage.StorageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 初始化默认本地存储与常用文件来源类型。重复启动保持幂等。
 */
@Component
public class SeedRunner implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(SeedRunner.class);

    private static final Map<String, String> DEFAULT_SOURCES = new LinkedHashMap<>();

    static {
        DEFAULT_SOURCES.put("USER", "用户中心");
        DEFAULT_SOURCES.put("ORDER", "订单");
        DEFAULT_SOURCES.put("PRODUCT", "商品");
        DEFAULT_SOURCES.put("ADMIN", "管理后台");
        DEFAULT_SOURCES.put("CONTENT", "内容管理");
        DEFAULT_SOURCES.put("SYSTEM", "系统任务");
    }

    private final AppProperties props;
    private final StorageProviderRepository providers;
    private final StorageProviderService providerService;
    private final FileSourceService sources;

    public SeedRunner(AppProperties props, StorageProviderRepository providers,
                      StorageProviderService providerService, FileSourceService sources) {
        this.props = props;
        this.providers = providers;
        this.providerService = providerService;
        this.sources = sources;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!props.seed.enabled) {
            return;
        }
        try {
            seedProvider();
        } catch (Exception e) {
            log.error("初始化默认存储提供者失败", e);
        }
        for (Map.Entry<String, String> entry : DEFAULT_SOURCES.entrySet()) {
            try {
                sources.ensure(entry.getKey(), entry.getValue(), "系统预置文件来源类型");
            } catch (Exception e) {
                log.warn("初始化文件来源类型失败 {}: {}", entry.getKey(), e.getMessage());
            }
        }
    }

    private void seedProvider() {
        String code = props.seed.localProviderCode;
        StorageProviderRow existing = providers.findByCode(code).orElse(null);
        if (existing == null) {
            boolean hasDefault = providers.findDefault().isPresent();
            providerService.create(new StorageProviderCommand(
                    code, "本地默认存储", StorageType.LOCAL,
                    null, null, null, props.storage.localRoot,
                    null, null, null, null,
                    true, !hasDefault, true, true, true, Map.of()));
            log.info("已初始化本地存储提供者 code={} root={}", code, props.storage.localRoot);
            return;
        }
        if (!existing.enabled()) {
            providerService.setEnabled(existing.id(), true);
        }
        if (providers.findDefault().isEmpty()) {
            providerService.setDefault(existing.id());
        }
    }
}
