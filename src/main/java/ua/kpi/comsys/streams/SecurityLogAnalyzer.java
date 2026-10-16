package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Gatherer;
import java.util.stream.Stream;

public class SecurityLogAnalyzer {

    public Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream) {
        if (stream == null) {
            throw new IllegalArgumentException("stream cannot be null");
        }

        return stream
                .filter(log -> log != null && "CRITICAL".equalsIgnoreCase(log.severityLevel()))
                .findFirst();
    }

    public List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline) {
        if (stream == null) {
            throw new IllegalArgumentException("stream cannot be null");
        }
        if (deadline == null) {
            throw new IllegalArgumentException("deadline cannot be null");
        }

        return stream
                .takeWhile(log -> log != null && log.timestamp().isBefore(deadline))
                .toList();
    }

    public List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport) {
        if (stream == null) {
            throw new IllegalArgumentException("stream cannot be null");
        }
        if (burstThreshold <= 0) {
            throw new IllegalArgumentException("burstThreshold must be greater than 0");
        }
        if (maxIpsToReport <= 0) {
            throw new IllegalArgumentException("maxIpsToReport must be greater than 0");
        }

        Gatherer<SecurityLog, BurstState, String> burstGatherer = Gatherer.ofSequential(
                BurstState::new,
                (state, element, downstream) -> {
                    if (element != null && element.ipAddress() != null) {
                        String ip = element.ipAddress();
                        if (ip.equals(state.currentIp)) {
                            state.currentCount++;
                        } else {
                            state.currentIp = ip;
                            state.currentCount = 1;
                            state.reported = false;
                        }

                        if (state.currentCount >= burstThreshold && !state.reported) {
                            state.reported = true;
                            downstream.push(ip);
                        }
                    } else {
                        state.currentIp = null;
                        state.currentCount = 0;
                        state.reported = false;
                    }
                    return !downstream.isRejecting();
                }
        );

        return stream
                .gather(burstGatherer)
                .limit(maxIpsToReport)
                .toList();
    }

    private static class BurstState {
        private String currentIp = null;
        private int currentCount = 0;
        private boolean reported = false;
    }
}