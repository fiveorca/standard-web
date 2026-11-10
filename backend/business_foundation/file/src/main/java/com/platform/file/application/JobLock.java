package com.platform.file.application;

import com.platform.file.shared.Db;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

/**
 * 基于数据库表的任务互斥锁。锁带过期时间，进程异常退出后不会永久阻塞定时任务。
 */
@Component
public class JobLock {
    private final Db db;
    private final String owner = UUID.randomUUID().toString();

    public JobLock(Db db) {
        this.db = db;
    }

    public boolean acquire(String name, long seconds) {
        Instant until = Instant.now().plusSeconds(Math.max(1, seconds));
        int rows = db.update("""
                INSERT INTO job_lock (name, owner, locked_until, updated_at)
                VALUES (:name, :owner, :until, now())
                ON CONFLICT (name) DO UPDATE
                SET owner = EXCLUDED.owner, locked_until = EXCLUDED.locked_until, updated_at = now()
                WHERE job_lock.locked_until < now()
                """, Db.params("name", name, "owner", owner, "until", until));
        return rows > 0;
    }

    public void release(String name) {
        db.update("DELETE FROM job_lock WHERE name = :name AND owner = :owner",
                Db.params("name", name, "owner", owner));
    }
}
