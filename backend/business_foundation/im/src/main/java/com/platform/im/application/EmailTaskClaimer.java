package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.repository.EmailTaskRepository;
import com.platform.im.shared.Ids;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 邮件任务抢占器：数据库行锁 + SKIP LOCKED，保证多实例下同一任务只被一个 Worker 处理。
 */
@Service
public class EmailTaskClaimer {
    private final EmailTaskRepository repository;
    private final AppProperties props;
    private final String workerId;

    public EmailTaskClaimer(EmailTaskRepository repository, AppProperties props) {
        this.repository = repository;
        this.props = props;
        String configured = props.email.workerId;
        this.workerId = configured == null || configured.isBlank()
                ? "im-email-" + hostname() + "-" + Ids.randomToken(4)
                : configured.trim();
    }

    @Transactional
    public List<UUID> claim(int limit) {
        List<UUID> ids = repository.lockClaimableIds(limit);
        List<UUID> claimed = new ArrayList<>(ids.size());
        for (UUID id : ids) {
            if (repository.claimTask(id, workerId) == 1) {
                claimed.add(id);
            }
        }
        return claimed;
    }

    @Transactional
    public int recoverStale() {
        Instant cutoff = Instant.now().minusSeconds(props.email.lockTimeoutSeconds);
        return repository.recoverStaleTasks(cutoff);
    }

    public String workerId() {
        return workerId;
    }

    private static String hostname() {
        String host = System.getenv("HOSTNAME");
        if (host == null || host.isBlank()) {
            host = System.getProperty("hostname", "local");
        }
        return host.replaceAll("[^A-Za-z0-9_-]", "").toLowerCase(java.util.Locale.ROOT);
    }
}
