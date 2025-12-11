#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

namespace yggdrasil_cpp_genkeys
{

/**
 * @class ThreadSafeQueue
 * @brief A thread-safe queue for passing objects between threads.
 *
 * This class provides a classic thread-safe queue, suitable for producer-consumer
 * scenarios. It uses a mutex to protect internal data from concurrent access
 * and a condition variable to allow threads to wait efficiently for new data.
 *
 * @tparam T The type of elements stored in the queue.
 */
template <typename T>
class ThreadSafeQueue
{
   public:
    /**
     * @brief Default constructor.
     *
     * Initializes an empty queue.
     */
    ThreadSafeQueue() = default;

    // Disable copying and moving to ensure the mutex and condition variable
    // are not unexpectedly shared or moved, which could lead to undefined behavior.
    ThreadSafeQueue(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue(ThreadSafeQueue&&) = delete;
    ThreadSafeQueue& operator=(ThreadSafeQueue&&) = delete;

    /**
     * @brief Pushes a new element to the back of the queue.
     *
     * This method is thread-safe and can be called by multiple producer threads.
     * After pushing the element, it will notify one waiting consumer thread.
     *
     * @param value The value to be copied into the queue.
     */
    void push_back(const T& value)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(value);
        }
        // Notify one waiting thread that a new item is available.
        // The lock is released before notifying to avoid a context switch
        // while the lock is held.
        condition_.notify_one();
    }

    /**
     * @brief Pushes a new element to the back of the queue by moving it.
     *
     * This method is thread-safe and can be called by multiple producer threads.
     * After pushing the element, it will notify one waiting consumer thread.
     *
     * @param value The value to be moved into the queue.
     */
    void push_back(T&& value)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(value));
        }
        condition_.notify_one();
    }

    /**
     * @brief Pops an element from the front of the queue, blocking if the queue is empty.
     *
     * This function will block the calling thread until an element is available.
     * It is designed for consumer threads in a producer-consumer pattern.
     *
     * @return The popped element from the front of the queue.
     */
    T pop_front()
    {
        std::unique_lock<std::mutex> lock(mutex_);

        // Wait until the queue is not empty.
        // The lambda is a predicate that prevents spurious wakeups.
        condition_.wait(lock, [this] { return !queue_.empty(); });

        T value = std::move(queue_.front());
        queue_.pop();
        return value;
    }

    /**
     * @brief Tries to pop an element from the front of the queue, with a timeout.
     *
     * This function will block the calling thread for up to the specified timeout
     * duration waiting for an element to become available.
     *
     * @tparam Rep The arithmetic type representing the number of ticks.
     * @tparam Period A std::ratio representing the tick period (e.g., std::milli).
     * @param timeout The maximum duration to wait.
     * @return An std::optional containing the popped value if an element became available,
     *         otherwise std::nullopt if the timeout was reached.
     */
    template <typename Rep, typename Period>
    std::optional<T> pop_front_for(
        const std::chrono::duration<Rep, Period>& timeout)
    {
        std::unique_lock<std::mutex> lock(mutex_);

        // Wait for the specified duration or until the queue is not empty.
        if (condition_.wait_for(lock, timeout,
                                [this] { return !queue_.empty(); })) {
            // Predicate is true, so the queue is not empty.
            T value = std::move(queue_.front());
            queue_.pop();
            return value;
        }
        else {
            // Timeout occurred, predicate is still false (queue is empty).
            return std::nullopt;
        }
    }

    /**
     * @brief Tries to pop an element from the front of the queue without blocking.
     *
     * If the queue is empty, the function returns immediately with std::nullopt.
     *
     * @return An std::optional containing the popped value if the queue was not empty,
     *         otherwise std::nullopt.
     */
    std::optional<T> try_pop_front()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) {
            return std::nullopt;
        }

        std::optional<T> value = std::move(queue_.front());
        queue_.pop();
        return value;
    }

    /**
     * @brief Checks if the queue is empty.
     *
     * @note This state may be stale by the time the function returns, as other
     * threads can modify the queue concurrently. This method is primarily for
     * debugging or diagnostics.
     *
     * @return True if the queue is empty, false otherwise.
     */
    bool empty() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

   private:
    mutable std::mutex mutex_;  ///< Mutex to protect access to the queue.
    std::queue<T> queue_;       ///< The underlying standard queue.
    std::condition_variable
        condition_;  ///< Condition variable for blocking pop operations.
};

}  // namespace yggdrasil_cpp_genkeys