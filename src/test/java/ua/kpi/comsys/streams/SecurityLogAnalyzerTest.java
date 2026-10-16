package ua.kpi.comsys.streams;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class SecurityLogAnalyzerTest {

    private final SecurityLogAnalyzer analyzer = new SecurityLogAnalyzer();

    @Test
    @Timeout(2)
    void testFindFirstCriticalEventInfiniteStream() {
        AtomicInteger counter = new AtomicInteger(0);

        Stream<SecurityLog> infiniteStream = Stream.generate(() -> {
            int current = counter.incrementAndGet();
            String level = (current == 101) ? "CRITICAL" : "INFO";
            return new SecurityLog("192.168.1." + current, level, "Event " + current, LocalDateTime.now());
        });

        Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(infiniteStream);

        assertTrue(result.isPresent());
        assertEquals("CRITICAL", result.get().severityLevel());
        assertEquals("192.168.1.101", result.get().ipAddress());
    }

    @Test
    void testFindFirstCriticalEventNotFoundAndNullSeverity() {
        Stream<SecurityLog> stream = Stream.of(
                new SecurityLog("10.0.0.1", "INFO", "Desc", LocalDateTime.now()),
                new SecurityLog("10.0.0.2", null, "No severity", LocalDateTime.now()),
                null,
                new SecurityLog("10.0.0.3", "WARNING", "Desc", LocalDateTime.now())
        );

        Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(stream);

        assertTrue(result.isEmpty());
    }

    @Test
    @Timeout(2)
    void testGetLogsBeforeDeadlineInfiniteStream() {
        LocalDateTime baseTime = LocalDateTime.of(2026, 1, 1, 12, 0, 0);
        LocalDateTime deadline = LocalDateTime.of(2026, 1, 1, 12, 10, 0);

        AtomicInteger minuteOffset = new AtomicInteger(0);

        Stream<SecurityLog> infiniteStream = Stream.generate(() -> {
            int mins = minuteOffset.getAndIncrement();
            return new SecurityLog("10.0.0.1", "INFO", "Log " + mins, baseTime.plusMinutes(mins));
        });

        List<SecurityLog> logs = analyzer.getLogsBeforeDeadline(infiniteStream, deadline);

        assertEquals(10, logs.size());
    }

    @Test
    void testGetLogsBeforeDeadlineStoppedByAfterDeadlineAndNull() {
        LocalDateTime deadline = LocalDateTime.of(2026, 1, 1, 12, 0, 0);

        Stream<SecurityLog> streamByDate = Stream.of(
                new SecurityLog("10.0.0.1", "INFO", "Before", deadline.minusMinutes(5)),
                new SecurityLog("10.0.0.2", "INFO", "After", deadline.plusMinutes(5))
        );
        List<SecurityLog> logsByDate = analyzer.getLogsBeforeDeadline(streamByDate, deadline);
        assertEquals(1, logsByDate.size());

        Stream<SecurityLog> streamByNull = Stream.of(
                new SecurityLog("10.0.0.1", "INFO", "Before", deadline.minusMinutes(5)),
                null
        );
        List<SecurityLog> logsByNull = analyzer.getLogsBeforeDeadline(streamByNull, deadline);
        assertEquals(1, logsByNull.size());
    }

    @Test
    @Timeout(2)
    void testDetectIpBurstsInfiniteStream() {
        AtomicInteger stepCounter = new AtomicInteger(0);

        Stream<SecurityLog> infiniteStream = Stream.generate(() -> {
            int step = stepCounter.getAndIncrement();
            String ip = "192.168.1." + (step / 5);
            return new SecurityLog(ip, "WARNING", "Request", LocalDateTime.now());
        });

        List<String> bursts = analyzer.detectIpBursts(infiniteStream, 3, 2);

        assertEquals(2, bursts.size());
        assertEquals("192.168.1.0", bursts.get(0));
        assertEquals("192.168.1.1", bursts.get(1));
    }

    @Test
    void testDetectIpBurstsEdgeCasesAndBranches() {
        Stream<SecurityLog> stream = Stream.of(
                null,                                                                                         // element == null
                new SecurityLog(null, "INFO", "No IP", LocalDateTime.now()),       // ip == null
                new SecurityLog("10.0.0.1", "INFO", "Req 1", LocalDateTime.now()), // currentCount = 1 (< threshold)
                new SecurityLog("10.0.0.1", "INFO", "Req 2", LocalDateTime.now()), // currentCount = 2 (burst reached, push)
                new SecurityLog("10.0.0.1", "INFO", "Req 3", LocalDateTime.now()), // currentCount = 3 (reported == true)
                new SecurityLog("10.0.0.2", "INFO", "Req 1", LocalDateTime.now()), // новий IP, maxIpsToReport=1 досягне ліміту
                new SecurityLog("10.0.0.2", "INFO", "Req 2", LocalDateTime.now()),
                new SecurityLog("10.0.0.2", "INFO", "Req 3", LocalDateTime.now())
        );

        List<String> bursts = analyzer.detectIpBursts(stream, 2, 1);

        assertEquals(1, bursts.size());
        assertEquals("10.0.0.1", bursts.get(0));
    }

    @Test
    void testNullArgumentsThrowException() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.findFirstCriticalEvent(null));
        assertThrows(IllegalArgumentException.class, () -> analyzer.getLogsBeforeDeadline(null, LocalDateTime.now()));
        assertThrows(IllegalArgumentException.class, () -> analyzer.getLogsBeforeDeadline(Stream.empty(), null));
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(null, 3, 1));
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(Stream.empty(), 0, 1));
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(Stream.empty(), 3, -1));
    }
}